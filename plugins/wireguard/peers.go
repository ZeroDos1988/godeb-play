package wireguard

import (
	"net/http"
	"sync"

	"godebplay/backend/core"
)

const iface = "wg0"

// writeMu serialises changes to wg0.conf.
var writeMu sync.Mutex

// PeerView merges wg0.conf and `wg show` for one peer.
type PeerView struct {
	Name            string   `json:"name,omitempty"`
	PublicKey       string   `json:"publicKey"`
	AllowedIPs      []string `json:"allowedIPs"`
	Endpoint        string   `json:"endpoint,omitempty"`
	LatestHandshake int64    `json:"latestHandshake"`
	RxBytes         int64    `json:"rxBytes"`
	TxBytes         int64    `json:"txBytes"`
	InConfig        bool     `json:"inConfig"`
	Live            bool     `json:"live"`
}

type interfaceView struct {
	Name       string   `json:"name"`
	PublicKey  string   `json:"publicKey,omitempty"`
	ListenPort string   `json:"listenPort,omitempty"`
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns"`
	Up         bool     `json:"up"`
}

type peersResponse struct {
	core.CommandEnvelope
	Path       string        `json:"path"`
	LiveDetail string        `json:"liveDetail,omitempty"`
	Interface  interfaceView `json:"interface"`
	Peers      []PeerView    `json:"peers"`
	// Configured is false while wg0.conf is missing; the UI then offers to
	// join a hub instead of showing sample data as editable.
	Configured bool     `json:"configured"`
	Role       RoleInfo `json:"role"`
}

func handlePeers(w http.ResponseWriter, r *http.Request) {
	resp := peersResponse{Path: configPath}
	resp.Command = []string{"wg", "show", iface, "dump"}

	content := sampleConfig
	dump := ""
	if data, err := core.ReadAdminFile(configPath); err != nil {
		resp.Mocked = true
		resp.Detail = err.Error()
		dump = sampleDump
	} else {
		content = string(data)
		resp.Configured = true
		resp.Role = DetectRole(content)
		res := core.RunAdmin(r.Context(), "wg", "show", iface, "dump")
		if res.Err != nil {
			resp.LiveDetail = res.Detail()
		} else {
			dump = res.Stdout
		}
	}

	cfg := ParseConfig(content)
	live := ParseDump(dump)

	resp.Interface = interfaceView{
		Name:       iface,
		PublicKey:  live.PublicKey,
		ListenPort: cfg.Interface.ListenPort,
		Addresses:  cfg.Interface.Addresses,
		DNS:        cfg.Interface.DNS,
		Up:         dump != "",
	}
	if resp.Interface.ListenPort == "" {
		resp.Interface.ListenPort = live.ListenPort
	}
	resp.Peers = MergePeers(cfg.Peers, live.Peers)
	core.WriteJSON(w, http.StatusOK, resp)
}

// MergePeers joins both sources by public key. Order follows wg0.conf, then
// peers only known to the kernel.
func MergePeers(conf []Peer, live []LivePeer) []PeerView {
	out := []PeerView{}
	index := map[string]int{}
	add := func(key string) *PeerView {
		if i, ok := index[key]; ok && key != "" {
			return &out[i]
		}
		out = append(out, PeerView{PublicKey: key, AllowedIPs: []string{}})
		if key != "" {
			index[key] = len(out) - 1
		}
		return &out[len(out)-1]
	}
	for _, p := range conf {
		v := add(p.PublicKey)
		v.Name = p.Name
		v.AllowedIPs = p.AllowedIPs
		v.Endpoint = p.Endpoint
		v.InConfig = true
	}
	for _, p := range live {
		v := add(p.PublicKey)
		v.Live = true
		if len(p.AllowedIPs) > 0 {
			v.AllowedIPs = p.AllowedIPs
		}
		if p.Endpoint != "" {
			v.Endpoint = p.Endpoint
		}
		v.LatestHandshake = p.LatestHandshake
		v.RxBytes = p.RxBytes
		v.TxBytes = p.TxBytes
	}
	return out
}

// RequestError carries the HTTP status for a rejected join request.
type RequestError struct {
	Status int
	Msg    string
}

func (e *RequestError) Error() string { return e.Msg }

func reject(status int, msg string) error { return &RequestError{Status: status, Msg: msg} }
