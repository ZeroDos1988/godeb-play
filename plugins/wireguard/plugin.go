package wireguard

import (
	"net/http"

	"godebplay/backend/core"
)

func init() {
	core.Register("wireguard", Mount)
}

const configPath = "/etc/wireguard/wg0.conf"

// Mount registers the WireGuard route.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/wireguard/status", handleStatus)
	mux.HandleFunc("GET /api/plugins/wireguard/peers", handlePeers)
	mux.HandleFunc("POST /api/plugins/wireguard/peers", handleCreate)
	mux.HandleFunc("GET /api/plugins/wireguard/peers/{id}/config", handleClientConfig)
	mux.HandleFunc("POST /api/plugins/wireguard/peers/{id}/delete-config", handleDeleteClientConfig)
	mux.HandleFunc("GET /api/plugins/wireguard/peers/{id}/qr", handleQR)
	mux.HandleFunc("GET /api/plugins/wireguard/peers/{id}/code", handleJoinCode)
	mux.HandleFunc("POST /api/plugins/wireguard/peers/{id}/send-email", handleSendEmail)
	mux.HandleFunc("POST /api/plugins/wireguard/join", handleJoin)
	mux.HandleFunc("GET /api/plugins/wireguard/trust", handleTrustStatus)
	mux.HandleFunc("POST /api/plugins/wireguard/trust", handleTrustSet)
	mux.HandleFunc("POST /api/plugins/wireguard/trust/sync", handleTrustSync)
	mux.HandleFunc("GET /api/plugins/wireguard/trust/info", handleTrustInfo)
	mux.HandleFunc("GET /api/plugins/wireguard/volltunnel", handleVolltunnelGet)
	mux.HandleFunc("POST /api/plugins/wireguard/volltunnel", handleVolltunnelSet)
	mountAndroid(mux)
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
