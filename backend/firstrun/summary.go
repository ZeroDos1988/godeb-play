package firstrun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/core"
	"godebplay/plugins/wireguard"
)

// Version is the running GoDeb version, set by main.
var Version = "dev"

// The summary answers "how is this server set up and how do I reach it?"
// after the wizard and at any later time (web UI, `godeb-play summary`). It
// holds no secrets: no private keys, no tokens, no passwords.

// Link is a way to reach the web UI.
type Link struct {
	Kind    string `json:"kind"` // translation key in the UI
	Label   string `json:"label"`
	URL     string `json:"url"`
	Note    string `json:"note,omitempty"`
	Command string `json:"command,omitempty"` // shell command the note refers to
}

// TunnelSummary describes wg0.
type TunnelSummary struct {
	Interface  string `json:"interface"`
	Address    string `json:"address"`              // this host in the tunnel
	Network    string `json:"network,omitempty"`    // tunnel network (hub)
	ListenPort int    `json:"listenPort,omitempty"` // hub
	Endpoint   string `json:"endpoint,omitempty"`   // what clients connect to (hub)
	PublicKey  string `json:"publicKey,omitempty"`
	Hub        string `json:"hub,omitempty"`        // peer: hub endpoint
	HubAddress string `json:"hubAddress,omitempty"` // peer: hub in the tunnel
}

// Summary is the setup overview.
type Summary struct {
	Hostname    string         `json:"hostname"`
	Version     string         `json:"version"`
	PublicIP    string         `json:"publicIp"`
	Generated   string         `json:"generated"`
	CompletedAt string         `json:"completedAt,omitempty"`
	Role        string         `json:"role"`   // hub, peer, none
	Access      string         `json:"access"` // tunnel, lan, local
	URLs        []Link         `json:"urls"`
	Tunnel      *TunnelSummary `json:"tunnel,omitempty"`
	LANCert     string         `json:"lanCert,omitempty"` // SHA-256 fingerprint of the LAN HTTPS certificate
	SSHPorts    []int          `json:"sshPorts"`
	Firewall    string         `json:"firewall"` // active, inactive, missing
	Rules       []string       `json:"rules"`
	Commands    []Link         `json:"commands"`
}

// BuildSummary collects the overview. It reads wg0.conf and ufw, so it runs
// in the agent (or as root on the CLI).
func BuildSummary(ctx context.Context) Summary {
	host, _ := os.Hostname()
	st := Load()
	access := LoadAccess()
	s := Summary{
		Hostname:    host,
		Version:     Version,
		PublicIP:    core.DefaultRoute(ctx).Src,
		Generated:   time.Now().Format(time.RFC3339),
		CompletedAt: st.CompletedAt,
		Role:        "none",
		Access:      access.Mode,
		SSHPorts:    core.SSHPorts(ctx),
		Firewall:    "missing",
		Rules:       []string{},
		URLs:        []Link{},
	}
	if s.SSHPorts == nil {
		s.SSHPorts = []int{}
	}
	role, _ := wireguard.CurrentRole()
	if role.Role != wireguard.RoleNone {
		s.Role = string(role.Role)
		s.Tunnel = tunnelSummary(ctx, role, s.PublicIP)
	}

	// How to reach the UI, best way first.
	if s.Tunnel != nil && s.Tunnel.Address != "" {
		l := Link{Kind: "tunnel", Label: "Über den WireGuard-Tunnel", URL: "http://" + net.JoinHostPort(s.Tunnel.Address, "8080"), Note: "WireGuard-Tunnel verbinden, dann im Browser öffnen."}
		if role.Role == wireguard.RolePeer {
			l.Kind, l.Note = "tunnelPeer", "Über den Tunnel des Hubs erreichbar (Handy oder Laptop mit dem Hub verbunden)."
		}
		s.URLs = append(s.URLs, l)
	}
	if addr := access.Addr(); addr != "" {
		s.URLs = append(s.URLs, Link{Kind: "lan", Label: "Im Heimnetz (HTTPS)", URL: "https://" + addr, Note: "Selbstsigniertes Zertifikat: Fingerprint unten vergleichen."})
		if fp, err := CertFingerprint(); err == nil {
			s.LANCert = fp
		}
	}
	sshHost := s.PublicIP
	if sshHost == "" {
		sshHost = host
	}
	sshPort := ""
	if len(s.SSHPorts) > 0 && s.SSHPorts[0] != 22 {
		sshPort = " -p " + strconv.Itoa(s.SSHPorts[0])
	}
	sshCmd := "ssh" + sshPort + " -L 8080:127.0.0.1:8080 root@" + sshHost
	s.URLs = append(s.URLs, Link{Kind: "ssh", Label: "Notzugang über SSH", URL: "http://127.0.0.1:8080", Note: "Vorher: " + sshCmd, Command: sshCmd})

	switch st := core.RunAdmin(ctx, "ufw", "status"); {
	case st.Err != nil:
	case strings.Contains(st.Stdout, "Status: active"):
		s.Firewall = "active"
		s.Rules = ParseUFWRules(st.Stdout)
	default:
		s.Firewall = "inactive"
	}
	s.Commands = []Link{
		{Kind: "summary", Label: "Diese Übersicht", URL: "godeb-play summary"},
		{Kind: "status", Label: "Status der Dienste", URL: "systemctl status godeb godeb-play-agent"},
		{Kind: "log", Label: "Log (nur Probleme)", URL: "journalctl -u godeb -u godeb-play-agent -p warning -b"},
		{Kind: "passwd", Label: "Passwort zurücksetzen", URL: "godeb-play user passwd <benutzer>"},
		{Kind: "reset2fa", Label: "2FA zurücksetzen", URL: "godeb-play 2fa reset <benutzer>"},
	}
	if role.Role == wireguard.RoleHub {
		s.Commands = append(s.Commands, Link{Kind: "site", Label: "Standort anlegen", URL: "godeb site add <name> --address <tunnel-ip>"})
	}
	return s
}

func tunnelSummary(ctx context.Context, role wireguard.RoleInfo, publicIP string) *TunnelSummary {
	t := &TunnelSummary{Interface: "wg0"}
	data, err := core.ReadAdminFile(wireguard.ConfigPath())
	if err != nil {
		return t
	}
	cfg := wireguard.ParseConfig(string(data))
	if res := core.RunAdmin(ctx, "wg", "show", "wg0", "public-key"); res.Err == nil {
		t.PublicKey = strings.TrimSpace(res.Stdout)
	}
	if role.Role == wireguard.RolePeer {
		t.Address, t.Hub = role.Address, role.Hub
		if hub, ok := wireguard.HubTunnelAddr(); ok {
			t.HubAddress = hub.String()
		}
		return t
	}
	for _, a := range cfg.Interface.Addresses {
		if p, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil && p.Addr().Is4() {
			t.Address, t.Network = p.Addr().String(), p.Masked().String()
			break
		}
	}
	t.ListenPort, _ = strconv.Atoi(cfg.Interface.ListenPort)
	if t.ListenPort > 0 && publicIP != "" {
		t.Endpoint = net.JoinHostPort(publicIP, strconv.Itoa(t.ListenPort))
	}
	return t
}

// ParseUFWRules keeps the rule lines of `ufw status`.
func ParseUFWRules(out string) []string {
	rules := []string{}
	started := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, " ")
		if strings.HasPrefix(line, "--") {
			started = true
			continue
		}
		if started && strings.TrimSpace(line) != "" {
			rules = append(rules, strings.Join(strings.Fields(line), " "))
		}
	}
	return rules
}

var roleNames = map[string]string{"hub": "WireGuard-Hub (Server)", "peer": "Peer eines Hubs (Standort)", "none": "ohne WireGuard"}
var accessNames = map[string]string{AccessTunnel: "nur über den WireGuard-Tunnel", AccessLAN: "Tunnel und Heimnetz (HTTPS)", AccessLocal: "nur lokal (SSH-Weiterleitung)"}

// WriteSummary prints the overview as text, for `godeb-play summary` and after
// `apt install` on a configured server.
func WriteSummary(w io.Writer, s Summary) {
	line := strings.Repeat("=", 66)
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "  GoDeb %s auf %s\n", s.Version, s.Hostname)
	fmt.Fprintln(w, line)
	fmt.Fprintln(w, "  Weboberfläche:")
	for _, l := range s.URLs {
		fmt.Fprintf(w, "    -> %-28s %s\n", l.Label, l.URL)
		if l.Note != "" {
			fmt.Fprintf(w, "       %s\n", l.Note)
		}
	}
	if s.LANCert != "" {
		fmt.Fprintf(w, "    Zertifikat SHA-256: %s\n", s.LANCert)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Rolle:          %s\n", roleNames[s.Role])
	fmt.Fprintf(w, "  Erreichbarkeit: %s\n", accessNames[s.Access])
	fmt.Fprintf(w, "  Öffentliche IP: %s\n", s.PublicIP)
	if t := s.Tunnel; t != nil {
		fmt.Fprintf(w, "  Tunnel-Adresse: %s (%s)\n", t.Address, t.Interface)
		if t.Network != "" {
			fmt.Fprintf(w, "  Tunnel-Netz:    %s\n", t.Network)
		}
		if t.Endpoint != "" {
			fmt.Fprintf(w, "  Endpoint:       %s (UDP)\n", t.Endpoint)
		}
		if t.Hub != "" {
			fmt.Fprintf(w, "  Hub:            %s, im Tunnel %s\n", t.Hub, t.HubAddress)
		}
	}
	ports := make([]string, len(s.SSHPorts))
	for i, p := range s.SSHPorts {
		ports[i] = strconv.Itoa(p)
	}
	fmt.Fprintf(w, "  SSH-Port:       %s\n", strings.Join(ports, ", "))
	fmt.Fprintf(w, "  Firewall (ufw): %s\n", s.Firewall)
	for _, r := range s.Rules {
		fmt.Fprintf(w, "    %s\n", r)
	}
	fmt.Fprintln(w, line)
}

func handleSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, BuildSummary(r.Context()))
}
