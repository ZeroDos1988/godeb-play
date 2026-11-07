package wireguard

import (
	"errors"
	"io/fs"
	"net/http"
	"sync"

	"godebplay/backend/core"
)

const iface = "wg0"

// writeMu serialises changes to wg0.conf and the clients directory.
var writeMu sync.Mutex

// PeerView merges wg0.conf, `wg show` and the client file of one peer.
type PeerView struct {
	ID              string   `json:"id,omitempty"`
	Name            string   `json:"name,omitempty"`
	PublicKey       string   `json:"publicKey"`
	AllowedIPs      []string `json:"allowedIPs"`
	Endpoint        string   `json:"endpoint,omitempty"`
	LatestHandshake int64    `json:"latestHandshake"`
	RxBytes         int64    `json:"rxBytes"`
	TxBytes         int64    `json:"txBytes"`
	InConfig        bool     `json:"inConfig"`
	Live            bool     `json:"live"`
	HasClient       bool     `json:"hasClient"`
	Created         string   `json:"created,omitempty"`
	Site            bool     `json:"site,omitempty"`
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
	Path       string `json:"path"`
	ClientsDir string `json:"clientsDir"`
	LiveDetail string `json:"liveDetail,omitempty"`
	// DefaultEndpoint is the server endpoint of an existing client, so new
	// peers do not inherit the tunnel address the UI was opened through.
	DefaultEndpoint string        `json:"defaultEndpoint,omitempty"`
	Interface       interfaceView `json:"interface"`
	Peers           []PeerView    `json:"peers"`
	// Configured is false while wg0.conf is missing; the UI then offers to
	// join a hub instead of showing sample data as editable.
	Configured bool     `json:"configured"`
	Role       RoleInfo `json:"role"`
}

func handlePeers(w http.ResponseWriter, r *http.Request) {
	resp := peersResponse{Path: configPath, ClientsDir: clientsDir}
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
	clients := []Client{}
	if !resp.Mocked {
		var err error
		clients, err = LoadClients()
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			resp.Detail = clientsDir + ": " + err.Error()
		}
	}

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
	resp.Peers = MergePeers(cfg.Peers, live.Peers, clients)
	for _, c := range clients {
		if c.Endpoint != "" {
			resp.DefaultEndpoint = c.Endpoint
			break
		}
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

// MergePeers joins the three sources by public key. Order follows wg0.conf,
// then peers only known to the kernel, then orphaned client files.
func MergePeers(conf []Peer, live []LivePeer, clients []Client) []PeerView {
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
	for _, c := range clients {
		v := add(c.PublicKey)
		v.ID = c.Name
		v.HasClient = true
		v.Created = c.Created
		v.Site = c.Site
		if v.Name == "" {
			v.Name = c.Name
		}
		if len(v.AllowedIPs) == 0 {
			v.AllowedIPs = c.Addresses
		}
	}
	return out
}

// PeerRequest describes a new client. The web UI and `godeb-play setup` both go
// through CreatePeer so wg0.conf, the clients directory and IPAM stay in sync.
type PeerRequest struct {
	Name        string `json:"name"`
	Endpoint    string `json:"endpoint"`
	DNS         string `json:"dns"`
	AllowedIPs  string `json:"allowedIPs"`
	ExcludedIPs string `json:"excludedIPs"`
	Address     string `json:"address"`
	Keepalive   *int   `json:"keepalive"`
	// Site creates the peer for a GoDeb host behind the hub: AllowedIPs is
	// the tunnel network only, no DNS, keepalive 25, and tunnel clients may
	// reach its web UI through the hub (SyncHubRoutes).
	Site bool `json:"site"`
	// PublicKey, when set, uses a key generated on the device: GoDeb stores
	// only the public key in wg0.conf and does not write a client file with
	// a private key. Mutually exclusive with Site.
	PublicKey string `json:"publicKey,omitempty"`
}

// RequestError carries the HTTP status for a rejected peer request.
type RequestError struct {
	Status int
	Msg    string
}

func (e *RequestError) Error() string { return e.Msg }

func reject(status int, msg string) error { return &RequestError{Status: status, Msg: msg} }
