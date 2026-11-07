package steam

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	"godebplay/backend/core"
	"godebplay/backend/logging"
	"godebplay/backend/metrics"
	"godebplay/plugins/wireguard"
)

func init() {
	core.Register("steam", Mount)
}

// Mount registers the routes. Every game route carries {game}, which must be
// a registered game ID. Install and update need a fresh 2FA code
// (backend/auth/stepup.go).
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/steam/games", handleGames)
	mux.HandleFunc("GET /api/plugins/steam/games/{game}/status", withGame(handleStatus))
	mux.HandleFunc("GET /api/plugins/steam/games/{game}/job", withGame(handleJob))
	mux.HandleFunc("POST /api/plugins/steam/games/{game}/install", withGame(handleStartJob("install", install)))
	mux.HandleFunc("POST /api/plugins/steam/games/{game}/update", withGame(handleStartJob("update", update)))
	mux.HandleFunc("POST /api/plugins/steam/games/{game}/action", withGame(handleAction))
	mux.HandleFunc("GET /api/plugins/steam/games/{game}/config", withGame(handleGetConfig))
	mux.HandleFunc("PUT /api/plugins/steam/games/{game}/config", withGame(handlePutConfig))
	mux.HandleFunc("GET /api/plugins/steam/games/{game}/logs", withGame(handleLogs))
	mux.HandleFunc("GET /api/plugins/steam/games/{game}/backups", withGame(handleBackups))
	mux.HandleFunc("POST /api/plugins/steam/games/{game}/backups", withGame(handleStartJob("backup", manualBackup)))
	mux.HandleFunc("POST /api/plugins/steam/games/{game}/backups/{name}/restore", withGame(handleRestore))
}

func withGame(fn func(http.ResponseWriter, *http.Request, *Game)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, ok := lookup(r.PathValue("game"))
		if !ok {
			core.WriteError(w, http.StatusNotFound, "Unbekanntes Spiel")
			return
		}
		fn(w, r, g)
	}
}

// gameInfo is the static description plus the state shown in the list.
type gameInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	AppID      string `json:"appId"`
	Platform   string `json:"platform"`
	DownloadGB int    `json:"downloadGb"`
	MemoryGB   int    `json:"memoryGb"`
	HasConfig  bool   `json:"hasConfig"`
	Installed  bool   `json:"installed"`
	Ready      bool   `json:"ready"`
	Service    string `json:"service"`
}

func info(ctx context.Context, g *Game) gameInfo {
	return gameInfo{
		ID: g.ID, Name: g.Name, AppID: g.AppID, Platform: g.Platform,
		DownloadGB: g.DownloadGB, MemoryGB: g.MemoryGB, HasConfig: g.ConfigFile != "",
		Installed: g.installed(), Ready: g.ready(), Service: serviceState(ctx, g),
	}
}

func handleGames(w http.ResponseWriter, r *http.Request) {
	out := []gameInfo{}
	for _, g := range sortedGames() {
		out = append(out, info(r.Context(), g))
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"games": out})
}

type statusResponse struct {
	core.CommandEnvelope
	gameInfo
	Unit       string `json:"unit"`
	User       string `json:"user"`
	BuildID    string `json:"buildId,omitempty"`
	ServerDir  string `json:"serverDir"`
	ConfigPath string `json:"configPath,omitempty"`
	Ports      []int  `json:"ports"`
	TCPPorts   []int  `json:"tcpPorts,omitempty"`
	Job        *Job   `json:"job"`
	// Hub is the public host of the GoDeb hub when this server is its peer;
	// players then connect to the hub, which forwards the ports.
	Hub        string `json:"hub,omitempty"`
	TunnelAddr string `json:"tunnelAddress,omitempty"`
}

func handleStatus(w http.ResponseWriter, r *http.Request, g *Game) {
	resp := statusResponse{
		gameInfo:   info(r.Context(), g),
		Unit:       g.unit(),
		User:       g.user(),
		BuildID:    buildID(g),
		ServerDir:  g.serverDir(),
		ConfigPath: g.configPath(),
		Ports:      g.currentPorts(),
		TCPPorts:   g.currentTCPPorts(),
		Job:        jobs.snapshot(g.ID),
	}
	resp.Command = []string{"systemctl", "is-active", g.unit()}
	if resp.Service == "unknown" {
		resp.Mocked = true
		resp.Detail = "systemctl nicht erreichbar"
	}
	if role, err := wireguard.CurrentRole(); err == nil && role.Role == wireguard.RolePeer {
		resp.Hub, resp.TunnelAddr = role.HubHost(), role.Address
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func handleJob(w http.ResponseWriter, r *http.Request, g *Game) {
	core.WriteJSON(w, http.StatusOK, map[string]any{"job": jobs.snapshot(g.ID)})
}

func handleStartJob(action string, fn func(context.Context, *Game, *jobHandle) error) func(http.ResponseWriter, *http.Request, *Game) {
	return func(w http.ResponseWriter, r *http.Request, g *Game) {
		if err := requireRoot(); err != nil {
			core.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		if action != "install" && !g.installed() {
			core.WriteError(w, http.StatusConflict, "Server ist noch nicht installiert")
			return
		}
		err := jobs.start(g.ID, action, func(ctx context.Context, j *jobHandle) error { return fn(ctx, g, j) })
		if err != nil {
			core.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		core.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true, "job": jobs.snapshot(g.ID)})
	}
}

type actionRequest struct {
	Action string `json:"action"`
}

func handleAction(w http.ResponseWriter, r *http.Request, g *Game) {
	var req actionRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	switch req.Action {
	case "start", "stop", "restart":
	default:
		core.WriteError(w, http.StatusBadRequest, "Aktion muss start, stop oder restart sein")
		return
	}
	if !g.ready() {
		core.WriteError(w, http.StatusConflict, "Server ist noch nicht installiert")
		return
	}
	res := core.RunAdmin(r.Context(), "systemctl", req.Action, g.unit())
	if res.Err != nil {
		emitGame(g, metrics.StatusWarning, actionText[req.Action]+" fehlgeschlagen", logging.User(r.Context()))
		core.WriteError(w, http.StatusBadGateway, res.Detail())
		return
	}
	emitGame(g, metrics.StatusInfo, actionText[req.Action], logging.User(r.Context()))
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "command": res.Command, "service": serviceState(r.Context(), g)})
}

type configResponse struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Exists  bool   `json:"exists"`
}

func handleGetConfig(w http.ResponseWriter, r *http.Request, g *Game) {
	if g.ConfigFile == "" {
		core.WriteError(w, http.StatusNotFound, g.Name+" hat keine Konfigurationsdatei")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	raw, err := g.readConfig()
	if errors.Is(err, os.ErrNotExist) {
		def, derr := g.DefaultConfig()
		if derr != nil {
			core.WriteError(w, http.StatusInternalServerError, derr.Error())
			return
		}
		core.WriteJSON(w, http.StatusOK, configResponse{Path: g.configPath(), Content: string(def)})
		return
	}
	if err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, configResponse{Path: g.configPath(), Content: string(raw), Exists: true})
}

type putConfigRequest struct {
	Content string `json:"content"`
	Restart bool   `json:"restart"`
}

// handlePutConfig stores the file exactly as sent after validating it. The
// form view and the raw editor both send the full text, so keys GoDeb does
// not know survive either way.
func handlePutConfig(w http.ResponseWriter, r *http.Request, g *Game) {
	if g.ConfigFile == "" {
		core.WriteError(w, http.StatusNotFound, g.Name+" hat keine Konfigurationsdatei")
		return
	}
	var req putConfigRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	cfg, err := g.ValidateConfig([]byte(req.Content))
	if err != nil {
		core.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	uid, gid := -1, -1
	if u, gr, err := lookupUser(g); err == nil {
		uid, gid = u, gr
	} else if os.Geteuid() == 0 {
		core.WriteError(w, http.StatusConflict, "Dienstkonto "+g.user()+" fehlt; zuerst installieren")
		return
	}
	content := []byte(req.Content)
	if !strings.HasSuffix(req.Content, "\n") {
		content = append(content, '\n')
	}
	if err := writeConfig(g, content, uid, gid); err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := writeSettings(g, cfg); err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	resp := map[string]any{"ok": true, "ports": g.Ports(cfg)}
	if req.Restart && serviceState(r.Context(), g) == "active" {
		if res := core.RunAdmin(r.Context(), "systemctl", "restart", g.unit()); res.Err != nil {
			resp["detail"] = "Gespeichert, Neustart fehlgeschlagen: " + res.Detail()
		} else {
			resp["restarted"] = true
		}
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func handleLogs(w http.ResponseWriter, r *http.Request, g *Game) {
	stdout, env := core.ReadCommand(r.Context(), "", "journalctl", "-u", g.unit(), "-n", "200", "--no-pager", "-o", "short-iso")
	core.WriteJSON(w, http.StatusOK, map[string]any{
		"command": env.Command,
		"mocked":  env.Mocked,
		"detail":  env.Detail,
		"lines":   strings.Split(strings.TrimRight(stdout, "\n"), "\n"),
	})
}

func serviceState(ctx context.Context, g *Game) string {
	res := core.RunQuiet(ctx, "systemctl", "is-active", g.unit())
	state := strings.TrimSpace(res.Stdout)
	if state == "" {
		return "unknown"
	}
	return strings.SplitN(state, "\n", 2)[0]
}

// buildID reads the installed build from the SteamCMD app manifest.
func buildID(g *Game) string {
	r, err := g.openBase()
	if err != nil {
		return ""
	}
	defer r.Close()
	raw, err := readLimited(r, serverSub+"/steamapps/appmanifest_"+g.AppID+".acf", 1<<20)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == `"buildid"` {
			return strings.Trim(fields[1], `"`)
		}
	}
	return ""
}
