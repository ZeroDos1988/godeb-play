package systemd

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"godebplay/backend/core"
)

func init() {
	core.Register("systemd", Mount)
	core.RegisterService("systemd", runAutoReboot)
}

var unitPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:._@-]{0,120}\.service$`)

// Mount registers the systemd routes.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/systemd/services", handleServices)
	mux.HandleFunc("GET /api/plugins/systemd/overview", handleOverview)
	mux.HandleFunc("POST /api/plugins/systemd/action", handleAction)
	mux.HandleFunc("GET /api/plugins/systemd/reboot", handleRebootStatus)
	mux.HandleFunc("POST /api/plugins/systemd/reboot", handleReboot)
	mux.HandleFunc("POST /api/plugins/systemd/reboot/cancel", handleRebootCancel)
	mux.HandleFunc("POST /api/plugins/systemd/reboot/settings", handleRebootSettings)
}

type listResponse struct {
	core.CommandEnvelope
	Services []Service `json:"services"`
}

type actionRequest struct {
	Unit   string `json:"unit"`
	Action string `json:"action"`
}

func handleServices(w http.ResponseWriter, r *http.Request) {
	stdout, env := core.ReadCommand(
		r.Context(),
		sampleUnits,
		"systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend",
	)
	core.WriteJSON(w, http.StatusOK, listResponse{
		CommandEnvelope: env,
		Services:        ParseUnits(stdout),
	})
}

func handleAction(w http.ResponseWriter, r *http.Request) {
	var req actionRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	req.Unit = strings.TrimSpace(req.Unit)
	if !validUnit(req.Unit) {
		core.WriteError(w, http.StatusBadRequest, "Unit-Name ist nicht erlaubt")
		return
	}
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		core.WriteError(w, http.StatusBadRequest, "Aktion muss start, stop oder restart sein")
		return
	}
	res := core.RunAdminTimeout(r.Context(), 2*time.Minute, "systemctl", req.Action, req.Unit)
	if res.Err != nil {
		core.WriteError(w, http.StatusBadGateway, res.Detail())
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"command": res.Command,
		"output":  strings.TrimSpace(res.Stdout),
	})
}

func validUnit(unit string) bool {
	// GoDeb's own units: stopping them from the UI would cut the UI off.
	return unitPattern.MatchString(unit) && unit != "godeb-play.service" && unit != "godeb-play-agent.service"
}
