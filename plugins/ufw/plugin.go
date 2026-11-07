package ufw

import (
	"net/http"
	"regexp"
	"strings"

	"godebplay/backend/core"
)

func init() {
	core.Register("ufw", Mount)
}

var rulePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}$`)

// Mount registers the UFW routes.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/ufw/status", handleStatus)
	mux.HandleFunc("POST /api/plugins/ufw/rules", handleRule)
	mux.HandleFunc("GET "+remoteBase, handleRemoteStatus)
	mux.HandleFunc("POST "+remoteBase, handleRemoteOpen)
	mux.HandleFunc("POST "+remoteBase+"/close", handleRemoteClose)
}

type statusResponse struct {
	core.CommandEnvelope
	Active bool   `json:"active"`
	Rules  []Rule `json:"rules"`
}

type ruleRequest struct {
	Action string `json:"action"`
	Rule   string `json:"rule"`
	Policy string `json:"policy"`
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	stdout, env := core.ReadCommand(r.Context(), sampleStatus, "ufw", "status")
	parsed := ParseStatus(stdout)
	core.WriteJSON(w, http.StatusOK, statusResponse{
		CommandEnvelope: env,
		Active:          parsed.Active,
		Rules:           parsed.Rules,
	})
}

func handleRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	req.Rule = strings.TrimSpace(strings.TrimSuffix(req.Rule, " (v6)"))
	if !validRule(req.Rule) {
		core.WriteError(w, http.StatusBadRequest, "Regel enthält unerlaubte Zeichen")
		return
	}

	args, ok := ruleArgs(req)
	if !ok {
		core.WriteError(w, http.StatusBadRequest, "Aktion muss allow, deny oder delete sein")
		return
	}
	res := core.RunAdmin(r.Context(), "ufw", args...)
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

func ruleArgs(req ruleRequest) ([]string, bool) {
	switch req.Action {
	case "allow", "deny":
		return []string{"--force", req.Action, req.Rule}, true
	case "delete":
		policy := strings.ToLower(req.Policy)
		if policy == "" {
			policy = "allow"
		}
		switch policy {
		case "allow", "deny", "reject", "limit":
			return []string{"--force", "delete", policy, req.Rule}, true
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func validRule(rule string) bool {
	return rulePattern.MatchString(rule) && !strings.Contains(rule, "..")
}
