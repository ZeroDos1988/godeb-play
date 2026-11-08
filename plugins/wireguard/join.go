package wireguard

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/core"
)

// joinConfig is a client configuration from a hub, reduced to the keys
// GoDeb accepts. Anything else is rejected: wg-quick runs PreUp/PostUp/...
// as root shell commands, so a pasted file must not carry them.
type joinConfig struct {
	PrivateKey   string
	Address      netip.Addr
	MTU          int
	PublicKey    string
	PresharedKey string
	Endpoint     string
	AllowedIPs   []netip.Prefix
	Keepalive    int
	Profile      SiteProfile
}

// JoinResult describes the written peer configuration.
type JoinResult struct {
	Address string   `json:"address"`
	Hub     string   `json:"hub"`
	Notes   []string `json:"notes"`
}

// parseJoinConfig validates a client file from a GoDeb hub (or any
// WireGuard server) for use as this host's wg0.
func parseJoinConfig(content string) (joinConfig, []string, error) {
	var jc joinConfig
	notes := []string{}
	section := ""
	sections := map[string]int{}
	for n, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if readProfileComment(line, &jc.Profile) {
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			if section != "interface" && section != "peer" {
				return jc, nil, fmt.Errorf("Zeile %d: unbekannter Abschnitt %s", n+1, line)
			}
			sections[section]++
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return jc, nil, fmt.Errorf("Zeile %d ist keine Schlüssel/Wert-Zeile", n+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		var err error
		switch section + "." + key {
		case "interface.privatekey":
			jc.PrivateKey, err = keyValue("PrivateKey", val)
		case "interface.address":
			jc.Address, err = joinAddress(val)
		case "interface.dns":
			notes = append(notes, "DNS = "+val+" wurde weggelassen; die Heim-VM behält ihren eigenen DNS-Server.")
		case "interface.mtu":
			jc.MTU, err = strconv.Atoi(val)
			if err != nil || jc.MTU < 1280 || jc.MTU > 9000 {
				err = fmt.Errorf("MTU muss zwischen 1280 und 9000 liegen")
			}
		case "peer.publickey":
			jc.PublicKey, err = keyValue("PublicKey", val)
		case "peer.presharedkey":
			jc.PresharedKey, err = keyValue("PresharedKey", val)
		case "peer.endpoint":
			jc.Endpoint, err = validEndpoint(val)
		case "peer.allowedips":
			for _, part := range splitList(val) {
				p, perr := netip.ParsePrefix(part)
				if perr != nil {
					return jc, nil, fmt.Errorf("AllowedIPs-Eintrag %q ist kein Netz", part)
				}
				jc.AllowedIPs = append(jc.AllowedIPs, p.Masked())
			}
		case "peer.persistentkeepalive":
			jc.Keepalive, err = strconv.Atoi(val)
			if err != nil || jc.Keepalive < 0 || jc.Keepalive > 65535 {
				err = fmt.Errorf("PersistentKeepalive muss zwischen 0 und 65535 liegen")
			}
		default:
			return jc, nil, fmt.Errorf("Zeile %d: %s ist in [%s] nicht erlaubt (wg-quick würde Befehle als root ausführen oder das Routing ändern)",
				n+1, strings.TrimSpace(raw[:strings.Index(raw, "=")]), section)
		}
		if err != nil {
			return jc, nil, fmt.Errorf("Zeile %d: %w", n+1, err)
		}
	}
	switch {
	case sections["interface"] != 1:
		return jc, nil, fmt.Errorf("genau ein [Interface]-Abschnitt nötig")
	case sections["peer"] != 1:
		return jc, nil, fmt.Errorf("genau ein [Peer]-Abschnitt nötig (der Hub)")
	case jc.PrivateKey == "" || jc.PublicKey == "":
		return jc, nil, fmt.Errorf("PrivateKey und PublicKey des Hubs fehlen")
	case !jc.Address.IsValid():
		return jc, nil, fmt.Errorf("Address fehlt")
	case jc.Endpoint == "":
		return jc, nil, fmt.Errorf("Endpoint des Hubs fehlt")
	case len(jc.AllowedIPs) == 0:
		return jc, nil, fmt.Errorf("AllowedIPs fehlt")
	}
	// Only the tunnel network goes through the hub. A full tunnel would send
	// the whole home connection (and SSH replies) via the VPS.
	for _, p := range jc.AllowedIPs {
		if !p.Addr().Is4() || p.Bits() < 8 || !p.Contains(jc.Address) {
			return jc, nil, fmt.Errorf("AllowedIPs %s: erlaubt ist nur das Tunnelnetz, das %s enthält (kein Volltunnel)", p, jc.Address)
		}
	}
	profile, err := jc.Profile.Normalize()
	if err != nil {
		return jc, nil, fmt.Errorf("Profil des Standorts: %w", err)
	}
	jc.Profile = profile
	if jc.Keepalive == 0 {
		jc.Keepalive = 25
		notes = append(notes, "PersistentKeepalive = 25 ergänzt, damit der Tunnel hinter NAT offen bleibt.")
	}
	return jc, notes, nil
}

func keyValue(name, val string) (string, error) {
	if !validKey(val) {
		return "", fmt.Errorf("%s ist kein WireGuard-Schlüssel", name)
	}
	return val, nil
}

func joinAddress(val string) (netip.Addr, error) {
	parts := splitList(val)
	if len(parts) != 1 {
		return netip.Addr{}, fmt.Errorf("Address: genau eine IPv4-Adresse erwartet")
	}
	if p, err := netip.ParsePrefix(parts[0]); err == nil && p.Addr().Is4() && p.Bits() == 32 {
		return p.Addr(), nil
	}
	if a, err := netip.ParseAddr(parts[0]); err == nil && a.Is4() {
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("Address muss eine IPv4-Adresse mit /32 sein")
}

// renderPeerConfig writes the normalised wg0.conf of a peer host. Only parsed
// values are written, never lines of the original file.
func renderPeerConfig(jc joinConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by GoDeb. This host is a peer of the WireGuard hub %s.\n", jc.Endpoint)
	fmt.Fprintf(&b, "# %s: %s\n", roleMarker, RolePeer)
	b.WriteString(jc.Profile.comments())
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", jc.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/32\n", jc.Address)
	if jc.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", jc.MTU)
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString("# Name = hub\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", jc.PublicKey)
	if jc.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", jc.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", jc.Endpoint)
	allowed := make([]string, len(jc.AllowedIPs))
	for i, p := range jc.AllowedIPs {
		allowed[i] = p.String()
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", jc.Keepalive)
	return b.String()
}

// JoinHub makes this host a peer of another GoDeb hub: it validates the
// client file the hub created (`godeb site add` or "Standort" in the UI) and
// writes it as wg0.conf. An existing wg0.conf is never replaced. The caller
// starts the tunnel with StartTunnel. `godeb-play setup --join` and the web UI
// both use this function.
func JoinHub(ctx context.Context, content string) (JoinResult, error) {
	content, err := decodeJoinInput(content)
	if err != nil {
		return JoinResult{}, reject(http.StatusBadRequest, err.Error())
	}
	jc, notes, err := parseJoinConfig(content)
	if err != nil {
		return JoinResult{}, reject(http.StatusBadRequest, err.Error())
	}
	rendered := renderPeerConfig(jc)
	writeMu.Lock()
	defer writeMu.Unlock()
	if existing, err := core.ReadAdminFile(configPath); err == nil {
		if string(existing) != rendered {
			return JoinResult{}, reject(http.StatusConflict, configPath+" existiert bereits und wird nicht ersetzt")
		}
		notes = append(notes, configPath+" ist bereits so eingerichtet.")
	} else if err := core.WriteAdminFile(configPath, []byte(rendered), 0o600); err != nil {
		return JoinResult{}, err
	}
	return JoinResult{Address: jc.Address.String(), Hub: jc.Endpoint, Notes: notes}, nil
}

type joinRequest struct {
	Config string `json:"config"`
}

type joinResponse struct {
	OK bool `json:"ok"`
	JoinResult
	Handshake bool   `json:"handshake"`
	Detail    string `json:"detail,omitempty"`
}

func handleJoin(w http.ResponseWriter, r *http.Request) {
	var req joinRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	res, err := JoinHub(r.Context(), req.Config)
	if err != nil {
		writeRequestError(w, err)
		return
	}
	resp := joinResponse{OK: true, JoinResult: res}
	if err := StartTunnel(r.Context()); err != nil {
		resp.Detail = "wg0.conf geschrieben, Tunnel nicht gestartet: " + err.Error()
	} else {
		resp.Handshake = WaitHandshake(r.Context(), 10*time.Second)
		if !resp.Handshake {
			resp.Detail = "Noch kein Handshake mit dem Hub. Endpoint, Port 51820/udp am Hub und den Peer auf dem Hub prüfen."
		}
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func writeRequestError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if reqErr, ok := err.(*RequestError); ok {
		status = reqErr.Status
	}
	core.WriteError(w, status, err.Error())
}
