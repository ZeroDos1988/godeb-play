package wireguard

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/core"
)

// Role tells how this host takes part in the tunnel network.
type Role string

const (
	// RoleNone: no wg0.conf yet.
	RoleNone Role = ""
	// RoleHub: wg0 is a server (ListenPort, clients as peers). The VPS.
	RoleHub Role = "hub"
	// RolePeer: wg0 is a client of another GoDeb hub. The home VM.
	RolePeer Role = "peer"
)

// roleMarker is written by JoinHub. The fallback below also recognises a
// client file that was copied in by hand.
const roleMarker = "GoDeb-Role"

// RoleInfo is the role plus, for a peer, its hub and own tunnel address.
type RoleInfo struct {
	Role    Role   `json:"role"`
	Hub     string `json:"hub,omitempty"`
	Address string `json:"address,omitempty"`
}

// HubHost is the host part of the hub endpoint, i.e. the public address
// under which forwarded services of a peer are reachable.
func (r RoleInfo) HubHost() string {
	host := r.Hub
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = strings.Trim(host[:i], "[]")
	}
	return host
}

// DetectRole reads the role from wg0.conf content.
func DetectRole(content string) RoleInfo {
	cfg := ParseConfig(content)
	marked := false
	for _, line := range strings.Split(content, "\n") {
		if v, ok := commentValue(strings.TrimSpace(line), roleMarker); ok && strings.HasPrefix(strings.TrimSpace(line), "#") {
			marked = v == string(RolePeer)
		}
	}
	peer := marked || (cfg.Interface.ListenPort == "" && len(cfg.Peers) == 1 && cfg.Peers[0].Endpoint != "")
	if !peer {
		return RoleInfo{Role: RoleHub}
	}
	info := RoleInfo{Role: RolePeer}
	if len(cfg.Peers) > 0 {
		info.Hub = cfg.Peers[0].Endpoint
	}
	for _, a := range cfg.Interface.Addresses {
		if addr, ok := hostAddr(a); ok && addr.Is4() {
			info.Address = addr.String()
			break
		}
		if p, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil && p.Addr().Is4() {
			info.Address = p.Addr().String()
			break
		}
	}
	return info
}

// CurrentRole reads /etc/wireguard/wg0.conf.
func CurrentRole() (RoleInfo, error) {
	data, err := core.ReadAdminFile(configPath)
	if errors.Is(err, fs.ErrNotExist) {
		return RoleInfo{Role: RoleNone}, nil
	}
	if err != nil {
		return RoleInfo{}, err
	}
	return DetectRole(string(data)), nil
}

// StartTunnel enables wg-quick@wg0 now and at boot.
func StartTunnel(ctx context.Context) error {
	if res := core.RunAdmin(ctx, "systemctl", "enable", "--now", "wg-quick@"+iface+".service"); res.Err != nil {
		return &core.CommandError{Result: res}
	}
	return nil
}

// WaitHandshake polls `wg show wg0 latest-handshakes` until a peer has
// completed a handshake or timeout passes.
func WaitHandshake(ctx context.Context, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		res := core.RunAdmin(ctx, "wg", "show", iface, "latest-handshakes")
		for _, line := range strings.Split(res.Stdout, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				if ts, err := strconv.ParseInt(fields[1], 10, 64); err == nil && ts > 0 {
					return true
				}
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(time.Second)
	}
}
