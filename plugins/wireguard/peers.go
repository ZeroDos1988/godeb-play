package wireguard

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/db"
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
	Volltunnel bool     `json:"volltunnel"`
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
	if !resp.Mocked && resp.Role.Role == RoleHub {
		resp.Volltunnel = VolltunnelEnabled()
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

type createResponse struct {
	OK       bool       `json:"ok"`
	Peer     PeerView   `json:"peer"`
	Live     bool       `json:"live"`
	Detail   string     `json:"detail,omitempty"`
	Commands [][]string `json:"commands"`
}

// PeerResult is a created peer plus its rendered client configuration.
type PeerResult struct {
	createResponse
	ClientConfig string `json:"-"`
}

// RequestError carries the HTTP status for a rejected peer request.
type RequestError struct {
	Status int
	Msg    string
}

func (e *RequestError) Error() string { return e.Msg }

func reject(status int, msg string) error { return &RequestError{Status: status, Msg: msg} }

func handleCreate(w http.ResponseWriter, r *http.Request) {
	var req PeerRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	res, err := CreatePeer(r.Context(), req)
	if err != nil {
		status := http.StatusBadGateway
		var reqErr *RequestError
		if errors.As(err, &reqErr) {
			status = reqErr.Status
		}
		core.WriteError(w, status, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusCreated, res.createResponse)
}

// CreatePeer validates req, appends the peer to wg0.conf, writes the client
// file, applies the peer live and records the address in IPAM.
func CreatePeer(ctx context.Context, req PeerRequest) (PeerResult, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !clientName.MatchString(req.Name) {
		return PeerResult{}, reject(http.StatusBadRequest, "Name: 1–32 Zeichen, nur Buchstaben, Ziffern, - und _")
	}
	endpoint, err := validEndpoint(req.Endpoint)
	if err != nil {
		return PeerResult{}, reject(http.StatusBadRequest, err.Error())
	}
	dns, err := validDNS(req.DNS)
	if err != nil {
		return PeerResult{}, reject(http.StatusBadRequest, err.Error())
	}
	pubKey := strings.TrimSpace(req.PublicKey)
	if pubKey != "" {
		if !validKey(pubKey) {
			return PeerResult{}, reject(http.StatusBadRequest, "PublicKey muss ein Base64-kodierter 32-Byte-WireGuard-Schlüssel sein")
		}
		if req.Site {
			return PeerResult{}, reject(http.StatusBadRequest, "Standort braucht einen privaten Schlüssel (Beitrittscode), kein PublicKey allein")
		}
	}
	if req.Site {
		// Filled in below from the server prefix; DNS would need resolvconf
		// on the site and is not needed there.
		req.AllowedIPs, req.ExcludedIPs, dns = "10.0.0.0/8", "", nil
	}
	if strings.TrimSpace(req.AllowedIPs) == "" {
		req.AllowedIPs = "0.0.0.0/0, ::/0"
	}
	allowedBase, err := validAllowedIPs(req.AllowedIPs)
	if err != nil {
		return PeerResult{}, reject(http.StatusBadRequest, err.Error())
	}
	allowed, excluded, err := ApplyExcludedIPs(req.AllowedIPs, req.ExcludedIPs)
	if err != nil {
		return PeerResult{}, reject(http.StatusBadRequest, err.Error())
	}
	keepalive := 25
	if req.Keepalive != nil {
		keepalive = *req.Keepalive
	}
	if keepalive < 0 || keepalive > 65535 {
		return PeerResult{}, reject(http.StatusBadRequest, "PersistentKeepalive muss zwischen 0 und 65535 liegen")
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	original, err := core.ReadAdminFile(configPath)
	if err != nil {
		return PeerResult{}, reject(http.StatusConflict, configPath+" nicht lesbar: "+err.Error())
	}
	cfg := ParseConfig(string(original))
	if role := DetectRole(string(original)); role.Role == RolePeer {
		return PeerResult{}, reject(http.StatusConflict, "Dieser Server ist Peer des Hubs "+role.Hub+". Neue Clients auf dem Hub anlegen.")
	}
	if req.Site {
		prefix, _, err := serverPrefix(cfg.Interface.Addresses)
		if err != nil {
			return PeerResult{}, reject(http.StatusConflict, err.Error())
		}
		allowedBase = []string{prefix.Masked().String()}
		allowed, excluded = allowedBase, nil
	}
	clients, err := LoadClients()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return PeerResult{}, reject(http.StatusBadGateway, clientsDir+": "+err.Error())
	}

	used := []string{}
	for _, p := range cfg.Peers {
		if strings.EqualFold(p.Name, req.Name) {
			return PeerResult{}, reject(http.StatusConflict, "Peer "+req.Name+" existiert bereits in "+configPath)
		}
		used = append(used, p.AllowedIPs...)
	}
	for _, c := range clients {
		if strings.EqualFold(c.Name, req.Name) {
			return PeerResult{}, reject(http.StatusConflict, "Client "+req.Name+" existiert bereits")
		}
		used = append(used, c.Addresses...)
	}
	reserved, err := db.HasPeer(req.Name)
	if err != nil {
		return PeerResult{}, reject(http.StatusInternalServerError, "IPAM nicht lesbar: "+err.Error())
	}
	if reserved {
		return PeerResult{}, reject(http.StatusConflict, "Für "+req.Name+" ist bereits eine Adresse reserviert")
	}
	addresses, err := db.PeerAddresses()
	if err != nil {
		return PeerResult{}, reject(http.StatusInternalServerError, "IPAM nicht lesbar: "+err.Error())
	}
	used = append(used, addresses...)
	if res := core.RunAdmin(ctx, "wg", "show", iface, "allowed-ips"); res.Err == nil {
		for _, line := range strings.Split(res.Stdout, "\n") {
			if fields := strings.Fields(line); len(fields) > 1 {
				used = append(used, fields[1:]...)
			}
		}
	}

	address, err := clientAddress(req, cfg.Interface.Addresses, used, len(sites(clients)) > 0)
	if err != nil {
		return PeerResult{}, reject(http.StatusConflict, err.Error())
	}

	serverKey, err := serverPublicKey(ctx, string(original))
	if err != nil {
		return PeerResult{}, err
	}
	var keys Keypair
	if pubKey != "" {
		keys.Public = pubKey
	} else {
		keys, err = GenerateKeypair(ctx)
		if err != nil {
			return PeerResult{}, err
		}
	}
	psk, err := GeneratePresharedKey(ctx)
	if err != nil {
		return PeerResult{}, err
	}

	created := time.Now()
	var clientConf string
	if pubKey == "" {
		var trust []TrustInfo
		if !req.Site {
			trust = trustForClients(ctx, clients)
		}
		clientConf = RenderClient(ClientSpec{
			Name:           req.Name,
			Keys:           keys,
			PresharedKey:   psk,
			Address:        address,
			DNS:            dns,
			ServerKey:      serverKey,
			Endpoint:       endpoint,
			AllowedIPs:     allowed,
			AllowedIPsBase: allowedBase,
			ExcludedIPs:    excluded,
			Keepalive:      keepalive,
			Created:        created,
			Site:           req.Site,
			Trust:          trust,
		})
	}
	serverConf := strings.TrimRight(string(original), "\n") + "\n" + RenderServerPeer(req.Name, keys.Public, psk, address)

	if err := core.WriteAdminFile(configPath, []byte(serverConf), 0o600); err != nil {
		return PeerResult{}, err
	}
	if clientConf != "" {
		if err := core.WriteAdminFile(clientPath(req.Name), []byte(clientConf), 0o600); err != nil {
			if rollback := core.WriteAdminFile(configPath, original, 0o600); rollback != nil {
				err = errors.Join(err, rollback)
			}
			return PeerResult{}, err
		}
	}

	setCmd := []string{"wg", "set", iface, "peer", keys.Public, "preshared-key", "/dev/stdin", "allowed-ips", address.String() + "/32"}
	cmds := [][]string{{"wg", "genpsk"}, setCmd}
	if pubKey == "" {
		cmds = append([][]string{{"wg", "genkey"}, {"wg", "pubkey"}}, cmds...)
	}
	resp := createResponse{
		OK: true,
		Peer: PeerView{
			ID:         req.Name,
			Name:       req.Name,
			PublicKey:  keys.Public,
			AllowedIPs: []string{address.String() + "/32"},
			InConfig:   true,
			HasClient:  clientConf != "",
			Created:    created.UTC().Format(time.RFC3339),
			Site:       req.Site,
		},
		Commands: cmds,
	}
	if pubKey != "" {
		resp.Detail = "Nur PublicKey hinterlegt – Client-Datei mit privatem Schlüssel liegt nicht auf dem Server."
	}
	res := core.RunAdminInput(ctx, psk+"\n", setCmd[0], setCmd[1:]...)
	if res.Err != nil {
		extra := "In " + configPath + " gespeichert, aber " + iface + " nicht live aktualisiert: " + res.Detail()
		if resp.Detail != "" {
			resp.Detail += " " + extra
		} else {
			resp.Detail = extra
		}
	} else {
		resp.Live = true
		resp.Peer.Live = true
	}
	if err := db.SavePeer(req.Name, keys.Public, address.String()); err != nil {
		extra := "IPAM-Eintrag fehlgeschlagen: " + err.Error()
		if resp.Detail != "" {
			resp.Detail += " " + extra
		} else {
			resp.Detail = extra
		}
	}
	if req.Site {
		if err := syncHubRoutes(ctx); err != nil {
			extra := "Weiterleitung zur Web-UI des Standorts nicht eingerichtet: " + err.Error()
			if resp.Detail != "" {
				resp.Detail += " " + extra
			} else {
				resp.Detail = extra
			}
		}
	}
	return PeerResult{createResponse: resp, ClientConfig: clientConf}, nil
}

// serverPublicKey prefers the running interface and falls back to deriving
// the key from PrivateKey in wg0.conf.
func serverPublicKey(ctx context.Context, conf string) (string, error) {
	res := core.RunAdmin(ctx, "wg", "show", iface, "public-key")
	if key := strings.TrimSpace(res.Stdout); res.Err == nil && validKey(key) {
		return key, nil
	}
	priv := interfaceValue(conf, "PrivateKey")
	if priv == "" {
		return "", errors.New(configPath + " enthält keinen PrivateKey")
	}
	return PublicKey(ctx, priv)
}

// readClient loads the raw client file for a validated {id} path value.
func readClient(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	id := r.PathValue("id")
	if !clientName.MatchString(id) {
		core.WriteError(w, http.StatusBadRequest, "Ungültige Peer-ID")
		return "", nil, false
	}
	data, err := core.ReadAdminFile(clientPath(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			core.WriteError(w, http.StatusNotFound, "Keine Client-Konfiguration für "+id)
		} else {
			core.WriteError(w, http.StatusBadGateway, err.Error())
		}
		return "", nil, false
	}
	return id, data, true
}

func handleClientConfig(w http.ResponseWriter, r *http.Request) {
	id, data, ok := readClient(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.conf"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// handleDeleteClientConfig removes the client .conf (private key) after the
// admin downloaded it. The peer in wg0.conf stays.
func handleDeleteClientConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !clientName.MatchString(id) {
		core.WriteError(w, http.StatusBadRequest, "Ungültige Peer-ID")
		return
	}
	if err := core.RemoveAdminFile(clientPath(id)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			core.WriteError(w, http.StatusNotFound, "Keine Client-Konfiguration für "+id)
			return
		}
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleJoinCode returns the client file as join code, for pasting into
// "Mit Hub verbinden" on a site. Like the file it holds the private key.
func handleJoinCode(w http.ResponseWriter, r *http.Request) {
	_, data, ok := readClient(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, map[string]string{"code": JoinCode(string(data))})
}

func handleQR(w http.ResponseWriter, r *http.Request) {
	_, data, ok := readClient(w, r)
	if !ok {
		return
	}
	png, err := RenderQR(r.Context(), data)
	if err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(png)
}

// RenderQR encodes a client configuration as PNG via qrencode.
func RenderQR(ctx context.Context, conf []byte) ([]byte, error) {
	res := core.RunInput(ctx, string(conf), "qrencode", "-t", "PNG", "-l", "M", "-s", "6", "-m", "2", "-o", "-")
	if res.Err != nil {
		return nil, errors.New("qrencode: " + res.Detail())
	}
	return []byte(res.Stdout), nil
}
