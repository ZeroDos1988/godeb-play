package steam

import (
	"context"
	"net/http"
	"time"

	"godebplay/backend/core"
)

type protonInstalled struct {
	Version string   `json:"version"`
	Pinned  bool     `json:"pinned"`
	UsedBy  []string `json:"usedBy"`
}

// handleProton lists the unpacked releases and which games use them.
func handleProton(w http.ResponseWriter, r *http.Request) {
	out := []protonInstalled{}
	for _, v := range installedProtons() {
		out = append(out, protonInstalled{Version: v, Pinned: v == protonPinned, UsedBy: protonUsers(v)})
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"pinned": protonPinned, "dir": protonsDir(), "installed": out})
}

// handleProtonReleases asks GitHub for releases (cached; ?refresh=1 asks
// again). Reading only: installing is handleUseProton.
func handleProtonReleases(w http.ResponseWriter, r *http.Request) {
	list, at, err := protonReleases(r.Context(), r.URL.Query().Get("refresh") == "1")
	if err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	latest := ""
	if len(list) > 0 {
		latest = list[0].Version
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"releases": list, "latest": latest, "checked": at.UTC().Format(time.RFC3339)})
}

type protonRequest struct {
	Version string `json:"version"`
}

// handleUseProton installs a release if needed and switches the game to it
// as a job. Needs a fresh 2FA code (backend/auth/stepup.go): it downloads
// and runs code that is not pinned in GoDeb Play.
func handleUseProton(w http.ResponseWriter, r *http.Request, g *Game) {
	var req protonRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	if !protonTag.MatchString(req.Version) {
		core.WriteError(w, http.StatusBadRequest, "Version muss die Form GE-Proton<Zahl>-<Zahl> haben")
		return
	}
	if g.Platform != Proton {
		core.WriteError(w, http.StatusBadRequest, g.Name+" läuft nicht unter GE-Proton")
		return
	}
	if !g.ready() {
		core.WriteError(w, http.StatusConflict, "Server ist noch nicht installiert")
		return
	}
	if err := requireRoot(); err != nil {
		core.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	if err := jobs.start(g.ID, "proton", func(ctx context.Context, j *jobHandle) error { return useProton(req.Version)(ctx, g, j) }); err != nil {
		core.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true, "job": jobs.snapshot(g.ID)})
}

// handleDeleteProton removes a release no game uses.
func handleDeleteProton(w http.ResponseWriter, r *http.Request) {
	var req protonRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	if err := requireRoot(); err != nil {
		core.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	if jobs.busy() {
		core.WriteError(w, http.StatusConflict, "Es läuft gerade ein Job; danach erneut versuchen")
		return
	}
	if err := deleteProton(req.Version); err != nil {
		core.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
