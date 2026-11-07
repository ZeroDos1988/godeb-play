package wireguard

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
)

func init() {
	metrics.RegisterSource("wireguard", metricsSource)
	metrics.RegisterCheck("wireguard", metricsCheck)
	metrics.RegisterNamer("wireguard", tunnelNames)
}

// HubTunnelAddr returns the hub's address inside the tunnel when this host
// is a peer: the first host of the hub's allowed prefix that contains this
// host's own tunnel address (10.8.0.1 for 10.8.0.2 in 10.8.0.0/24).
func HubTunnelAddr() (netip.Addr, bool) {
	data, err := core.ReadAdminFile(configPath)
	if err != nil {
		return netip.Addr{}, false
	}
	content := string(data)
	role := DetectRole(content)
	own, err := netip.ParseAddr(role.Address)
	if role.Role != RolePeer || err != nil {
		return netip.Addr{}, false
	}
	return hubFromConfig(ParseConfig(content), own)
}

func hubFromConfig(cfg Config, own netip.Addr) (netip.Addr, bool) {
	for _, p := range cfg.Peers {
		for _, a := range p.AllowedIPs {
			pre, err := netip.ParsePrefix(strings.TrimSpace(a))
			if err != nil || pre.Bits() == 0 || !pre.Contains(own) {
				continue
			}
			hub := pre.Masked().Addr().Next()
			if hub.IsValid() && hub != own {
				return hub, true
			}
		}
	}
	return netip.Addr{}, false
}

// tunnelNames maps tunnel addresses to peer names for the connection list.
func tunnelNames() map[string]string {
	data, err := core.ReadAdminFile(configPath)
	if err != nil {
		return nil
	}
	cfg := ParseConfig(string(data))
	role := DetectRole(string(data))
	out := map[string]string{}
	for _, p := range cfg.Peers {
		for _, a := range p.AllowedIPs {
			ip, _, _ := strings.Cut(strings.TrimSpace(a), "/")
			if ip == "" || strings.HasPrefix(a, "0.0.0.0") {
				continue
			}
			name := p.Name
			if role.Role == RolePeer {
				name = "Hub"
			}
			if name != "" {
				out[ip] = name
			}
		}
	}
	return out
}

// onlineWindow: a peer with a handshake this recent counts as connected.
const onlineWindow = 3 * time.Minute

var (
	namesMu  sync.Mutex
	namesAt  time.Time
	namesOK  bool
	names    map[string]string // public key -> peer name
	roleSeen RoleInfo
)

// peerNames maps public keys to the "# Name" comments of wg0.conf; the file
// is read at most once a minute.
func peerNames() (map[string]string, RoleInfo, bool) {
	namesMu.Lock()
	defer namesMu.Unlock()
	if !namesAt.IsZero() && time.Since(namesAt) < time.Minute {
		return names, roleSeen, namesOK
	}
	namesAt = time.Now()
	data, err := core.ReadAdminFile(configPath)
	if err != nil {
		names, roleSeen, namesOK = nil, RoleInfo{}, false
		return nil, RoleInfo{}, false
	}
	content := string(data)
	m := map[string]string{}
	for _, p := range ParseConfig(content).Peers {
		m[p.PublicKey] = p.Name
	}
	names, roleSeen, namesOK = m, DetectRole(content), true
	return names, roleSeen, true
}

// peerSeries is the series part for a peer: its name, else the key start.
func peerSeries(names map[string]string, key string) string {
	if n := strings.TrimSpace(names[key]); n != "" {
		return metrics.SeriesPart(n)
	}
	k := key
	if len(k) > 8 {
		k = k[:8]
	}
	return "key-" + metrics.SeriesPart(k)
}

func liveDump(ctx context.Context) (LiveInterface, bool) {
	out, env := core.ReadCommand(ctx, "", "wg", "show", iface, "dump")
	if env.Mocked {
		return LiveInterface{}, false
	}
	return ParseDump(out), true
}

func metricsSource(ctx context.Context) []metrics.Sample {
	names, _, ok := peerNames()
	if !ok {
		return nil
	}
	live, ok := liveDump(ctx)
	if !ok {
		return nil
	}
	now := time.Now().Unix()
	online := 0
	var out []metrics.Sample
	for _, p := range live.Peers {
		name := peerSeries(names, p.PublicKey)
		label := names[p.PublicKey]
		if label == "" {
			label = name
		}
		out = append(out,
			// wg counts from the host's view: rx is what the peer sent.
			metrics.Sample{Series: "wg:" + name + ":rx", Value: float64(p.RxBytes), Counter: true, Unit: "B/s", Label: label + " empfangen"},
			metrics.Sample{Series: "wg:" + name + ":tx", Value: float64(p.TxBytes), Counter: true, Unit: "B/s", Label: label + " gesendet"},
		)
		if p.LatestHandshake > 0 && now-p.LatestHandshake < int64(onlineWindow/time.Second) {
			online++
		}
	}
	return append(out, metrics.Sample{Series: "wg.online", Value: float64(online), Label: "Verbundene Peers"})
}

func metricsCheck(ctx context.Context) []metrics.Finding {
	_, role, ok := peerNames()
	if !ok || role.Role == RoleNone {
		return nil
	}
	live, up := liveDump(ctx)
	if !up {
		return []metrics.Finding{{ID: "wireguard", Status: metrics.StatusCritical, Title: "WireGuard-Tunnel wg0 ist nicht aktiv", Detail: "systemctl status wg-quick@wg0"}}
	}
	if role.Role == RolePeer {
		var last int64
		for _, p := range live.Peers {
			last = max(last, p.LatestHandshake)
		}
		if last == 0 || time.Now().Unix()-last > int64(onlineWindow/time.Second) {
			return []metrics.Finding{{ID: "wireguard:hub", Status: metrics.StatusCritical, Title: "Keine Verbindung zum Hub", Detail: "Kein WireGuard-Handshake mit " + role.Hub + " in den letzten 3 Minuten. Weitergeleitete Spiele sind von außen nicht erreichbar."}}
		}
	}
	return nil
}
