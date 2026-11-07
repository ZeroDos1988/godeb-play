package wireguard

import (
	"net/http"

	"godebplay/backend/core"
)

func init() {
	core.Register("wireguard", Mount)
}

const configPath = "/etc/wireguard/wg0.conf"

// Mount registers the WireGuard routes. GoDeb Play is always a site of a
// GoDeb hub (or runs without WireGuard): status, the hub peer, joining.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/wireguard/status", handleStatus)
	mux.HandleFunc("GET /api/plugins/wireguard/peers", handlePeers)
	mux.HandleFunc("POST /api/plugins/wireguard/join", handleJoin)
}

type response struct {
	Path      string    `json:"path"`
	Command   []string  `json:"command"`
	Mocked    bool      `json:"mocked"`
	Detail    string    `json:"detail,omitempty"`
	Redacted  []string  `json:"redacted"`
	Interface Interface `json:"interface"`
	Peers     []Peer    `json:"peers"`
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := response{
		Path:    configPath,
		Command: []string{"cat", configPath},
	}
	data, err := core.ReadAdminFile(configPath)
	content := sampleConfig
	if err != nil {
		resp.Mocked = true
		resp.Detail = err.Error()
	} else {
		content = string(data)
	}
	cfg := ParseConfig(content)
	resp.Redacted = cfg.Redacted
	resp.Interface = cfg.Interface
	resp.Peers = cfg.Peers
	core.WriteJSON(w, http.StatusOK, resp)
}

// ConfigPath is the wg-quick file of the tunnel to the hub.
func ConfigPath() string { return configPath }
