package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"godebplay/backend/agent"
	"godebplay/backend/auth"
	"godebplay/backend/core"
	"godebplay/backend/db"
	"godebplay/backend/firstrun"
	"godebplay/backend/logging"
	"godebplay/backend/pluginmgr"
)

// runAgent is `godeb-play agent`: the root half of GoDeb. It has no network
// listener, only the Unix socket the web process forwards to.
func runAgent(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", agent.SocketPath(), "Unix-Socket (Standard "+agent.DefaultSocket+")")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sock == "" {
		*sock = agent.DefaultSocket
	}
	if os.Geteuid() != 0 {
		slog.Warn("Agent läuft nicht als root, Systemänderungen schlagen fehl (nur für Entwicklung)")
	}
	root, err := core.RepoRoot()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := db.Open(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	firstrun.MigrateWireGuard()
	handler, err := newAgentHandler(root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	webUser := agent.WebUser()
	ln, err := agent.Listen(*sock, agent.AllowedPeers(webUser), webUser)
	if err != nil {
		fmt.Fprintf(stderr, "agent: %v\n", err)
		return 1
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	core.Default.StartServices(ctx)
	slog.Info("GoDeb-Agent lauscht", "version", version, "socket", *sock, "web_benutzer", webUser, "log_level", os.Getenv("GODEB_LOG_LEVEL"))
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "agent: %v\n", err)
		return 1
	}
	return 0
}

// newAgentHandler mounts what the web process forwards: plugin routes, the
// plugin manager and the privileged setup steps. Login and step-up were
// checked by the web process; agent.Guard refuses every other path.
func newAgentHandler(root string) (http.Handler, error) {
	mux := http.NewServeMux()
	pluginsDir := filepath.Join(root, "plugins")
	plugins, err := core.Default.Load(pluginsDir, mux)
	if err != nil {
		return nil, err
	}
	pluginmgr.Mount(mux, pluginsDir)
	firstrun.MountPrivileged(mux)
	slog.Info("Plugins geladen", "anzahl", len(plugins), "pfad", pluginsDir)

	// Forwarded browser requests pass the agent's own 2FA check; internal
	// routes are called by the web process itself.
	guard := auth.NewAgentGuard()
	internal := http.NewServeMux()
	mountAgentInternal(internal)
	mountAgent2FA(internal, guard)
	forwarded := guard.Gate(agent.UserHeader, agent.SessionHeader, pluginGate(mux))
	// The agent's own audit log: who changed what, with the result. A
	// compromised web process can lie about the IP, but cannot hide that a
	// change ran here.
	return logging.Audit(agent.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, agent.InternalPrefix) {
			internal.ServeHTTP(w, r)
			return
		}
		forwarded.ServeHTTP(w, r)
	})), logging.AuditOptions{
		User: agent.User,
		IP:   agent.ClientIP,
		Quiet: func(r *http.Request) bool {
			return strings.HasPrefix(r.URL.Path, agent.InternalPrefix)
		},
	}), nil
}
