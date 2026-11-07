package wireguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
)

// The trusted endpoint lets the GoDeb Tunnel app notice that the phone is
// on the home network and switch the tunnel off there. The phone sends a
// random nonce over Wi-Fi (outside the tunnel); this host signs it with its
// trust key. The app only trusts a signature that verifies against the key
// pinned in its tunnel configuration (# GoDeb-Trusted-Key), so a foreign
// network cannot fake "home" by answering on the same address.
//
// Protocol godeb-trust-v1:
//
//	GET http://<lan-ip>:<port>/godeb-trust?nonce=<16..128 chars [A-Za-z0-9_-]>
//	200 {"v":1,"nonce":"<nonce>","sig":"<base64 DER ECDSA P-256 / SHA-256>"}
//	signed message: "godeb-trust-v1\n" + nonce (UTF-8)
//	key: base64 DER SubjectPublicKeyInfo (X509EncodedKeySpec on Android)
const (
	trustConfigPath  = "/etc/godeb-play/trust.json"
	trustKeyPath     = "/etc/godeb-play/trust.key"
	trustPath        = "/godeb-trust"
	trustMessage     = "godeb-trust-v1\n"
	trustRuleTag     = "GoDeb Trusted Endpoint"
	defaultTrustPort = 8787
	// maxTrustInFlight bounds concurrent signatures so the open LAN port
	// cannot be used to burn CPU.
	maxTrustInFlight = 8
)

var trustNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// TrustConfig is /etc/godeb-play/trust.json.
type TrustConfig struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"` // LAN IPv4 of this host
	Port    int    `json:"port"`
	Iface   string `json:"iface"`  // interface carrying Address
	Prefix  string `json:"prefix"` // LAN subnet allowed to reach the port
}

// TrustInfo is what a client configuration needs to pin this endpoint.
type TrustInfo struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url,omitempty"`
	Key     string `json:"key,omitempty"`
	Name    string `json:"name,omitempty"`
}

func (c TrustConfig) url() string {
	return "http://" + net.JoinHostPort(c.Address, strconv.Itoa(c.Port)) + trustPath
}

func loadTrustConfig() (TrustConfig, error) {
	data, err := core.ReadAdminFile(trustConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		return TrustConfig{Port: defaultTrustPort}, nil
	}
	if err != nil {
		return TrustConfig{}, err
	}
	var c TrustConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return TrustConfig{}, fmt.Errorf("%s: %w", trustConfigPath, err)
	}
	return c, nil
}

// loadTrustKey reads the signing key, creating it on first use.
func loadTrustKey(create bool) (*ecdsa.PrivateKey, error) {
	data, err := core.ReadAdminFile(trustKeyPath)
	if errors.Is(err, fs.ErrNotExist) && create {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := core.WriteAdminFile(trustKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New(trustKeyPath + " ist kein PKCS#8-Schlüssel")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New(trustKeyPath + " ist kein P-256-Schlüssel")
	}
	return key, nil
}

func publicKeyB64(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// fingerprint is a short, human-comparable form of the public key.
func fingerprint(keyB64 string) string {
	sum := sha256.Sum256([]byte(keyB64))
	return hex.EncodeToString(sum[:8])
}

// signTrust answers one probe.
func signTrust(key *ecdsa.PrivateKey, nonce string) (string, error) {
	digest := sha256.Sum256([]byte(trustMessage + nonce))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// verifyTrust is the check the app performs; used by tests and by
// `godeb-play trust test`.
func verifyTrust(keyB64, nonce, sigB64 string) bool {
	der, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(trustMessage + nonce))
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

// TrustSource gives the listener its config and signs probes. Locally that
// is trust.json and trust.key; with the root agent the web process asks the
// agent, so the signing key never leaves root.
type TrustSource interface {
	Config(ctx context.Context) (TrustConfig, error)
	Sign(ctx context.Context, nonce string) (string, error)
}

type localTrust struct{}

func (localTrust) Config(context.Context) (TrustConfig, error) { return loadTrustConfig() }

func (localTrust) Sign(_ context.Context, nonce string) (string, error) {
	key, err := loadTrustKey(false)
	if err != nil {
		return "", err
	}
	return signTrust(key, nonce)
}

// LocalTrustSource reads the files directly (in-process mode, agent).
func LocalTrustSource() TrustSource { return localTrust{} }

// TrustSign signs a probe with the local key; the agent's internal route.
func TrustSign(nonce string) (string, error) {
	if !trustNonce.MatchString(nonce) {
		return "", reject(http.StatusBadRequest, "nonce")
	}
	cfg, err := loadTrustConfig()
	if err != nil {
		return "", err
	}
	if !cfg.Enabled {
		return "", reject(http.StatusConflict, "Trusted Endpoint ist aus")
	}
	return localTrust{}.Sign(context.Background(), nonce)
}

// TrustSettings is the saved config; the agent's internal route.
func TrustSettings() (TrustConfig, error) { return loadTrustConfig() }

// trustHandler is the only handler on the LAN listener.
func trustHandler(src TrustSource) http.Handler {
	slots := make(chan struct{}, maxTrustInFlight)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+trustPath, func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		nonce := r.URL.Query().Get("nonce")
		if !trustNonce.MatchString(nonce) {
			http.Error(w, "nonce", http.StatusBadRequest)
			return
		}
		sig, err := src.Sign(r.Context(), nonce)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"v": 1, "nonce": nonce, "sig": sig})
	})
	return mux
}

// trustServer runs the LAN listener and restarts it when the config changes.
var trustServer struct {
	mu     sync.Mutex
	srv    *http.Server
	err    string
	daemon bool // set by WatchTrust; only that process owns the listener
	src    TrustSource
	cfg    TrustConfig // config the listener runs with
	seen   bool
	remote bool // set by TrustListenerElsewhere in the root agent
}

// WatchTrust runs in the web process: it starts the listener and restarts it
// whenever /etc/godeb-play/trust.json changes, so `godeb-play trust enable` and the
// agent (separate processes) take effect without restarting GoDeb. The
// listener is network-facing and therefore never runs in the root agent.
func WatchTrust(ctx context.Context, src TrustSource) {
	trustServer.mu.Lock()
	trustServer.daemon, trustServer.src = true, src
	trustServer.mu.Unlock()
	for {
		cfg, err := src.Config(ctx)
		trustServer.mu.Lock()
		changed := !trustServer.seen || cfg != trustServer.cfg
		trustServer.mu.Unlock()
		if changed && (err == nil || !trustServer.seen) {
			startTrust(ctx, src, cfg, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// TrustListenerElsewhere tells this process (the root agent) that the web
// process runs the listener: SetTrust waits for it and the status probes it.
func TrustListenerElsewhere() {
	trustServer.mu.Lock()
	trustServer.remote = true
	trustServer.mu.Unlock()
}

// startTrust (re)starts the listener with cfg. It is called at daemon
// start and after every change.
func startTrust(ctx context.Context, src TrustSource, cfg TrustConfig, cfgErr error) {
	trustServer.mu.Lock()
	defer trustServer.mu.Unlock()
	if trustServer.srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = trustServer.srv.Shutdown(sctx)
		cancel()
		trustServer.srv = nil
	}
	trustServer.err, trustServer.cfg, trustServer.seen = "", cfg, true
	if cfgErr != nil || !cfg.Enabled {
		if cfgErr != nil {
			trustServer.err = cfgErr.Error()
		}
		return
	}
	// Fail early when the key is missing or the agent cannot sign.
	if _, err := src.Sign(ctx, "godeb-selftest-0000"); err != nil {
		trustServer.err = err.Error()
		slog.Error("Trusted Endpoint", "fehler", err)
		return
	}
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		trustServer.err = err.Error()
		slog.Error("Trusted Endpoint", "fehler", err)
		return
	}
	srv := &http.Server{
		Handler:           trustHandler(src),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    4 << 10,
	}
	trustServer.srv = srv
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Trusted Endpoint", "fehler", err)
		}
	}()
	slog.Info("Trusted Endpoint lauscht", "adresse", addr)
}

func trustRunning() (bool, string) {
	trustServer.mu.Lock()
	remote := trustServer.remote
	running, msg := trustServer.srv != nil, trustServer.err
	trustServer.mu.Unlock()
	if !remote {
		return running, msg
	}
	if cfg, err := loadTrustConfig(); err != nil || !cfg.Enabled {
		return false, ""
	}
	if WaitTrustListening(time.Second) {
		return true, ""
	}
	return false, "Der Listener der Weboberfläche antwortet nicht (journalctl -u godeb)"
}

// ufwTrustRule allows the LAN subnet only, on the LAN interface only.
func ufwTrustRule(c TrustConfig) []string {
	return []string{"in", "on", c.Iface, "from", c.Prefix, "to", c.Address, "port", strconv.Itoa(c.Port), "proto", "tcp", "comment", trustRuleTag}
}

// SetTrust enables or disables the trusted endpoint. address "" picks the
// LAN address of the default route. The web UI and `godeb-play trust` use it.
func SetTrust(ctx context.Context, enabled bool, address string, port int) (TrustConfig, error) {
	old, err := loadTrustConfig()
	if err != nil {
		return TrustConfig{}, err
	}
	next := TrustConfig{Enabled: enabled, Port: port}
	if next.Port == 0 {
		next.Port = defaultTrustPort
	}
	if enabled {
		if next.Port < 1024 || next.Port > 65535 || next.Port == siteUIPort {
			return TrustConfig{}, reject(http.StatusBadRequest, "Port muss zwischen 1024 und 65535 liegen und darf nicht 8080 sein")
		}
		if address == "" {
			address = core.DefaultRoute(ctx).Src
		}
		var found *core.LANAddress
		for _, a := range core.LANAddresses() {
			if a.Address == address {
				a := a
				found = &a
			}
		}
		if found == nil {
			return TrustConfig{}, reject(http.StatusBadRequest, "Adresse "+address+" ist keine private IPv4-Adresse eines LAN-Interfaces dieses Servers")
		}
		next.Address, next.Iface, next.Prefix = found.Address, found.Iface, found.Prefix
		if _, err := loadTrustKey(true); err != nil {
			return TrustConfig{}, err
		}
	} else {
		next = old
		next.Enabled = false
	}
	if ufwAvailable(ctx) {
		if old.Enabled && old.Iface != "" {
			core.RunAdmin(ctx, "ufw", append([]string{"--force", "delete", "allow"}, ufwTrustRule(old)...)...)
		}
		if next.Enabled {
			if res := core.RunAdmin(ctx, "ufw", append([]string{"allow"}, ufwTrustRule(next)...)...); res.Err != nil {
				return TrustConfig{}, fmt.Errorf("ufw: %s", res.Detail())
			}
		}
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return TrustConfig{}, err
	}
	if err := core.WriteAdminFile(trustConfigPath, append(raw, '\n'), 0o600); err != nil {
		return TrustConfig{}, err
	}
	trustServer.mu.Lock()
	daemon, remote := trustServer.daemon, trustServer.remote
	trustServer.mu.Unlock()
	switch {
	case daemon:
		trustServer.mu.Lock()
		src := trustServer.src
		trustServer.mu.Unlock()
		cfg, err := src.Config(ctx)
		startTrust(ctx, src, cfg, err)
		if running, msg := trustRunning(); next.Enabled && !running {
			return next, fmt.Errorf("gespeichert, aber der Listener startet nicht: %s", msg)
		}
	case remote && next.Enabled:
		if !WaitTrustListening(8 * time.Second) {
			return next, errors.New("gespeichert, aber der Listener der Weboberfläche antwortet nicht (journalctl -u godeb)")
		}
	}
	return next, nil
}

// WaitTrustListening waits until the daemon serves the endpoint; used by the
// CLI, which only writes the config.
func WaitTrustListening(timeout time.Duration) bool {
	cfg, err := loadTrustConfig()
	if err != nil || !cfg.Enabled {
		return false
	}
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp4", addr, time.Second); err == nil {
			conn.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func ufwAvailable(ctx context.Context) bool {
	return core.RunAdminQuiet(ctx, "ufw", "status").Err == nil
}

// LocalTrust describes this host's endpoint for client configurations.
func LocalTrust() TrustInfo {
	cfg, err := loadTrustConfig()
	if err != nil || !cfg.Enabled {
		return TrustInfo{}
	}
	key, err := loadTrustKey(false)
	if err != nil {
		return TrustInfo{}
	}
	pub, err := publicKeyB64(key)
	if err != nil {
		return TrustInfo{}
	}
	host, _ := os.Hostname()
	return TrustInfo{Enabled: true, URL: cfg.url(), Key: pub, Name: host}
}

var trustURL = regexp.MustCompile(`^http://([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})/godeb-trust$`)

// valid checks trust info received from a site before it goes into client
// files: a private IPv4 URL of the fixed shape and a P-256 public key.
func (t TrustInfo) valid() bool {
	m := trustURL.FindStringSubmatch(t.URL)
	if !t.Enabled || m == nil {
		return false
	}
	if ip, err := netip.ParseAddr(m[1]); err != nil || !ip.IsPrivate() {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(t.Key)
	if err != nil {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	pub, ok := parsed.(*ecdsa.PublicKey)
	return err == nil && ok && pub.Curve == elliptic.P256()
}

// siteTrust asks a site over the tunnel for its trusted endpoint.
func siteTrust(ctx context.Context, addr string) (TrustInfo, bool) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(addr, strconv.Itoa(siteUIPort))+"/api/plugins/wireguard/trust/info", nil)
	if err != nil {
		return TrustInfo{}, false
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return TrustInfo{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TrustInfo{}, false
	}
	var t TrustInfo
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 4<<10)).Decode(&t); err != nil || !t.valid() {
		return TrustInfo{}, false
	}
	return t, true
}

// trustForClients collects the endpoints a new phone or laptop config should
// pin: this host's own and those of all sites behind this hub.
func trustForClients(ctx context.Context, clients []Client) []TrustInfo {
	out := []TrustInfo{}
	if local := LocalTrust(); local.valid() {
		out = append(out, local)
	}
	for _, c := range clients {
		if !c.Site {
			continue
		}
		for _, a := range c.Addresses {
			if addr, ok := hostAddr(a); ok {
				if t, ok := siteTrust(ctx, addr.String()); ok {
					out = append(out, t)
				}
			}
		}
	}
	return out
}

// renderTrustComments are the client file lines the app reads.
func renderTrustComments(list []TrustInfo) string {
	var b strings.Builder
	for _, t := range list {
		fmt.Fprintf(&b, "# GoDeb-Trusted-Endpoint: %s\n", t.URL)
		fmt.Fprintf(&b, "# GoDeb-Trusted-Key: %s\n", t.Key)
	}
	return b.String()
}

// replaceTrustComments swaps the trust lines of an existing client file.
func replaceTrustComments(content string, list []TrustInfo) string {
	var kept []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if _, ok := commentValue(trimmed, "GoDeb-Trusted-Endpoint"); ok && strings.HasPrefix(trimmed, "#") {
			continue
		}
		if _, ok := commentValue(trimmed, "GoDeb-Trusted-Key"); ok && strings.HasPrefix(trimmed, "#") {
			continue
		}
		kept = append(kept, line)
	}
	body := strings.Join(kept, "\n")
	i := strings.Index(body, "[Interface]")
	if i < 0 {
		return body
	}
	return body[:i] + renderTrustComments(list) + body[i:]
}

// SyncClientTrust rewrites the trust lines of every non-site client file on
// this hub, e.g. after a site enabled its endpoint. Phones must re-import
// the file (QR) afterwards. Returns the number of changed files.
func SyncClientTrust(ctx context.Context) (int, error) {
	writeMu.Lock()
	defer writeMu.Unlock()
	clients, err := LoadClients()
	if err != nil {
		return 0, err
	}
	list := trustForClients(ctx, clients)
	changed := 0
	for _, c := range clients {
		if c.Site {
			continue
		}
		data, err := core.ReadAdminFile(clientPath(c.Name))
		if err != nil {
			return changed, err
		}
		next := replaceTrustComments(string(data), list)
		if next == string(data) {
			continue
		}
		if err := core.WriteAdminFile(clientPath(c.Name), []byte(next), 0o600); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

type trustStatus struct {
	Config      TrustConfig       `json:"config"`
	Running     bool              `json:"running"`
	Error       string            `json:"error,omitempty"`
	URL         string            `json:"url,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Candidates  []core.LANAddress `json:"candidates"`
	Mocked      bool              `json:"mocked"`
	Detail      string            `json:"detail,omitempty"`
}

func handleTrustStatus(w http.ResponseWriter, r *http.Request) {
	resp := trustStatus{Candidates: core.LANAddresses()}
	cfg, err := loadTrustConfig()
	if err != nil {
		resp.Mocked, resp.Detail = true, err.Error()
	}
	resp.Config = cfg
	resp.Running, resp.Error = trustRunning()
	if info := LocalTrust(); info.Enabled {
		resp.URL, resp.Fingerprint = info.URL, fingerprint(info.Key)
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

type trustRequest struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func handleTrustSet(w http.ResponseWriter, r *http.Request) {
	var req trustRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := SetTrust(r.Context(), req.Enabled, strings.TrimSpace(req.Address), req.Port); err != nil {
		writeRequestError(w, err)
		return
	}
	handleTrustStatus(w, r)
}

// handleTrustInfo is read by the hub over the tunnel when it writes client
// files. It is public (see auth.protected): it only reveals the public key
// and a LAN address, and the UI listener is bound to loopback and wg0.
func handleTrustInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, LocalTrust())
}

func handleTrustSync(w http.ResponseWriter, r *http.Request) {
	n, err := SyncClientTrust(r.Context())
	if err != nil {
		writeRequestError(w, err)
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": n})
}
