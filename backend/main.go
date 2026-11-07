package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"godebplay/backend/agent"
	"godebplay/backend/auth"
	"godebplay/backend/authlog"
	"godebplay/backend/core"
	"godebplay/backend/db"
	"godebplay/backend/firstrun"
	"godebplay/backend/logging"
	"godebplay/backend/pluginmgr"
)

// Plugin packages register themselves from init() via core.Register.
// Blank-import each plugin from backend/modules.go. The loader mounts a
// plugin only when plugins/<id>/manifest.json is present on disk.

func main() {
	component := "web"
	if len(os.Args) > 1 {
		component = "cli"
		if os.Args[1] == "agent" {
			component = "agent"
		}
	}
	logging.Setup(component)
	firstrun.Version = version
	if len(os.Args) > 1 {
		os.Exit(runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}

	root, err := core.RepoRoot()
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("GODEB_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	authLog := authlog.New()
	handler, err := newHandler(root, func(r *http.Request, username string) {
		authLog.FailedLogin(core.ClientIP(r), username)
	})
	if err != nil {
		log.Fatal(err)
	}
	slog.Info("Fehlgeschlagene Logins werden zusätzlich für fail2ban protokolliert", "pfad", authLog.Path())
	if _, err := db.Open(); err != nil {
		log.Fatal(err)
	}
	if agent.SocketPath() == "" {
		firstrun.Migrate()
	} else {
		// The agent checks wg0.conf (root only), this process the accounts.
		firstrun.MigrateUsers()
	}
	if firstrun.Required() {
		if _, err := firstrun.EnsureToken(); err != nil {
			slog.Error("Einrichtungs-Token nicht angelegt", "fehler", err)
		}
	}

	specs, err := parseListen(addr)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("GoDeb Play startet", "version", version, "root", root, "auth", auth.Dir(), "db", db.Path(), "log_level", os.Getenv("GODEB_LOG_LEVEL"))
	if err := serveAll(ctx, srv, specs); err != nil {
		log.Fatal(err)
	}
	go newTLSListeners(handler).run(ctx)
	if agent.SocketPath() == "" {
		// Without an agent this process runs the plugins and their services.
		core.Default.StartServices(ctx)
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("Herunterfahren", "fehler", err)
	}
}

func newHandler(root string, fail auth.FailureFunc) (http.Handler, error) {
	mux := http.NewServeMux()
	pluginsDir := filepath.Join(root, "plugins")
	var plugins []core.Meta
	var err error
	if sock := agent.SocketPath(); sock != "" {
		// Split mode: the root agent mounts and runs the plugins, this
		// process only knows their sidebar entries and forwards.
		if plugins, err = core.Default.Scan(pluginsDir); err != nil {
			return nil, err
		}
		client := agent.NewClient(sock)
		// Weg 2+: 2FA secrets and the step-up check of agent routes live in
		// the agent; this process only forwards codes.
		sf := newAgentSecondFactor(client)
		auth.SetSecondFactor(sf)
		auth.DelegateStepUp(agent.Routed)
		mountAgentProxy(mux, agent.NewProxy(sock, sessionIdentity, auth.ApplyAgentVerdict))
		useAgentState(client)
		mountDoctorAPI(mux, client)
		go scrubWebSecrets(sf)
		firstrun.MountPublic(mux)
		slog.Info("Plugins gefunden, ausgeführt vom Agenten", "anzahl", len(plugins), "pfad", pluginsDir, "socket", sock)
	} else {
		if plugins, err = core.Default.Load(pluginsDir, mux); err != nil {
			return nil, err
		}
		firstrun.Mount(mux)
		pluginmgr.Mount(mux, pluginsDir)
		mountDoctorAPI(mux, nil)
		slog.Info("Plugins geladen", "anzahl", len(plugins), "pfad", pluginsDir)
	}

	auth.Mount(mux, fail)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		core.WriteJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"service": "godeb-play",
			"version": version,
		})
	})
	mux.HandleFunc("GET /api/plugins", func(w http.ResponseWriter, r *http.Request) {
		active := make([]core.Meta, 0, len(plugins))
		for _, p := range plugins {
			if !pluginmgr.IsDisabled(p.ID) {
				active = append(active, p)
			}
		}
		core.WriteJSON(w, http.StatusOK, map[string]any{"plugins": active})
	})
	mux.HandleFunc("GET /api/system", func(w http.ResponseWriter, r *http.Request) {
		core.WriteJSON(w, http.StatusOK, core.CollectSystem(r.Context()))
	})

	dist := filepath.Join(root, "frontend", "dist")
	if info, err := os.Stat(dist); err == nil && info.IsDir() {
		mux.Handle("/", spaHandler(dist))
	}
	audited := logging.Audit(auth.RequireSession(pluginGate(mux)), logging.AuditOptions{
		User: func(r *http.Request) string {
			if !isAPI(r.URL.Path) {
				return ""
			}
			u, _ := auth.SessionUser(r)
			return u
		},
		IP: core.ClientIP,
		// Static files are not logged; the agent logs the requests it
		// serves, with the result it knows.
		Skip: func(r *http.Request, status int) bool {
			if !isAPI(r.URL.Path) {
				return true
			}
			return agent.SocketPath() != "" && agent.Routed(r.URL.Path) && status < 400
		},
	})
	return withSecurityHeaders(core.WithCORS(audited)), nil
}

func isAPI(p string) bool {
	p = path.Clean("/" + p)
	return p == "/api" || strings.HasPrefix(p, "/api/")
}

// mountAgentProxy forwards the agent's routes. Login, step-up and the
// plugin gate have already run when a request gets here (see newHandler).
func mountAgentProxy(mux *http.ServeMux, proxy http.Handler) {
	mux.Handle("/api/plugins/", proxy)
	manager := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
		if r.Method != http.MethodGet {
			// The agent may have switched a plugin on or off.
			pluginmgr.Reload()
		}
	})
	mux.Handle("/api/plugin-manager", manager)
	mux.Handle("/api/plugin-manager/", manager)
	for _, p := range agent.PrivilegedSetupRoutes() {
		mux.Handle(p, proxy)
	}
}

// scrubWebSecrets removes the TOTP secrets of the web database copy once
// the agent answers for the same enrollments.
func scrubWebSecrets(sf auth.SecondFactor) {
	for attempt := 0; attempt < 30; attempt++ {
		kept, err := auth.ScrubLocalSecrets(sf)
		if err == nil {
			return
		}
		if len(kept) > 0 && attempt == 29 {
			slog.Warn("2FA-Daten liegen nur in der Web-Datenbank; sudo godeb-play 2fa reset <benutzer>", "benutzer", kept)
		}
		time.Sleep(2 * time.Second)
	}
}

func sessionIdentity(r *http.Request) agent.Identity {
	user, id, err := auth.SessionIdentity(r)
	if err != nil {
		return agent.Identity{}
	}
	return agent.Identity{User: user, Session: id}
}

// pluginGate answers 404 for the routes of a plugin that is switched off in
// the plugin manager, so a disabled plugin offers no attack surface. The
// plugin manager itself (/api/plugin-manager) stays reachable to switch it
// back on.
func pluginGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(path.Clean("/"+r.URL.Path), "/api/plugins/"); ok {
			id, _, _ := strings.Cut(rest, "/")
			if id != "" && pluginmgr.IsDisabled(id) {
				core.WriteError(w, http.StatusNotFound, "Plugin "+id+" ist deaktiviert")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
