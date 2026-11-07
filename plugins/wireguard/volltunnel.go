package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"godebplay/backend/core"
	"godebplay/plugins/ufw"
)

const (
	volltunnelStatePath = "/etc/godeb-play/volltunnel.json"
	volltunnelNftPath   = "/etc/godeb-play/volltunnel.nft"
	volltunnelUnit      = "godeb-volltunnel.service"
	volltunnelTable     = "godeb_volltunnel"
	volltunnelRouteTag  = "GoDeb-VT"
)

var (
	volltunnelMu    sync.Mutex
	volltunnelIface = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,14}$`)
)

type volltunnelState struct {
	Enabled bool `json:"enabled"`
}

// VolltunnelEnabled reports whether hub NAT for client internet egress is on.
func VolltunnelEnabled() bool {
	data, err := core.ReadAdminFile(volltunnelStatePath)
	if err != nil {
		return false
	}
	var s volltunnelState
	return json.Unmarshal(data, &s) == nil && s.Enabled
}

// ApplyVolltunnel turns hub internet egress on or off: IP forwarding, an
// nftables MASQUERADE table (like portforward, not ufw before.rules) and a
// matching ufw route allow from wg0 to the public interface.
func ApplyVolltunnel(ctx context.Context, enabled bool) error {
	volltunnelMu.Lock()
	defer volltunnelMu.Unlock()
	return applyVolltunnel(ctx, enabled)
}

func applyVolltunnel(ctx context.Context, enabled bool) error {
	data, err := core.ReadAdminFile(configPath)
	if err != nil {
		return fmt.Errorf("%s nicht lesbar: %w", configPath, err)
	}
	if role := DetectRole(string(data)); role.Role != RoleHub {
		return errors.New("Volltunnel gibt es nur auf dem Hub")
	}
	route := core.DefaultRoute(ctx)
	publicIf := route.Dev
	if !volltunnelIface.MatchString(publicIf) || publicIf == iface {
		return fmt.Errorf("öffentliches Interface %q nicht erkannt", publicIf)
	}

	previous, _ := core.ReadAdminFile(volltunnelNftPath)
	script := renderVolltunnelNft(publicIf, enabled)
	if err := core.WriteAdminFile(volltunnelNftPath+".new", []byte(script), 0o600); err != nil {
		return err
	}
	defer os.Remove(volltunnelNftPath + ".new")
	if res := core.RunAdmin(ctx, "nft", "-c", "-f", volltunnelNftPath+".new"); res.Err != nil {
		return fmt.Errorf("nftables lehnt die Regeln ab: %s", res.Detail())
	}
	if enabled {
		if err := core.EnableIPv4Forwarding(ctx); err != nil {
			return fmt.Errorf("IP-Forwarding: %w", err)
		}
	}
	if err := core.WriteAdminFile(volltunnelNftPath, []byte(script), 0o600); err != nil {
		return err
	}
	if res := core.RunAdmin(ctx, "nft", "-f", volltunnelNftPath); res.Err != nil {
		restoreVolltunnelNft(ctx, previous)
		return fmt.Errorf("nft -f: %s", res.Detail())
	}

	want := []ufw.RouteRule{}
	if enabled {
		want = append(want, ufw.RouteRule{
			In: iface, Out: publicIf,
			Comment: volltunnelRouteTag + " internet",
		})
	}
	if err := ufw.SyncRoutes(ctx, volltunnelRouteTag, want); err != nil {
		restoreVolltunnelNft(ctx, previous)
		return fmt.Errorf("ufw: %w", err)
	}

	raw, err := json.MarshalIndent(volltunnelState{Enabled: enabled}, "", "  ")
	if err != nil {
		return err
	}
	if err := core.WriteAdminFile(volltunnelStatePath, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if enabled {
		if res := core.RunAdmin(ctx, "systemctl", "enable", volltunnelUnit); res.Err != nil {
			return fmt.Errorf("Volltunnel aktiv, aber %s nicht aktiviert: %s", volltunnelUnit, res.Detail())
		}
	} else {
		core.RunAdmin(ctx, "systemctl", "disable", volltunnelUnit)
	}
	return nil
}

func restoreVolltunnelNft(ctx context.Context, previous []byte) {
	if previous == nil {
		previous = []byte(renderVolltunnelNft("", false))
	}
	if core.WriteAdminFile(volltunnelNftPath, previous, 0o600) == nil {
		core.RunAdmin(ctx, "nft", "-f", volltunnelNftPath)
	}
}

// renderVolltunnelNft replaces the GoDeb Volltunnel table atomically.
func renderVolltunnelNft(publicIf string, enabled bool) string {
	var b strings.Builder
	b.WriteString("# Managed by GoDeb (plugins/wireguard volltunnel). Changes are overwritten.\n")
	fmt.Fprintf(&b, "table ip %s\ndelete table ip %s\n", volltunnelTable, volltunnelTable)
	if !enabled {
		return b.String()
	}
	fmt.Fprintf(&b, "table ip %s {\n", volltunnelTable)
	b.WriteString("\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname %q oifname %q masquerade\n", iface, publicIf)
	b.WriteString("\t}\n}\n")
	return b.String()
}

type volltunnelRequest struct {
	Enabled bool `json:"enabled"`
}

type volltunnelResponse struct {
	core.CommandEnvelope
	Enabled    bool   `json:"enabled"`
	Forwarding bool   `json:"forwarding"`
	PublicIf   string `json:"publicIf,omitempty"`
	TableLive  bool   `json:"tableLive"`
	Unit       string `json:"unit,omitempty"`
}

func handleVolltunnelGet(w http.ResponseWriter, r *http.Request) {
	core.WriteJSON(w, http.StatusOK, volltunnelStatus(r.Context()))
}

func handleVolltunnelSet(w http.ResponseWriter, r *http.Request) {
	var req volltunnelRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	if err := ApplyVolltunnel(r.Context(), req.Enabled); err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, volltunnelStatus(r.Context()))
}

func volltunnelStatus(ctx context.Context) volltunnelResponse {
	resp := volltunnelResponse{
		Enabled:    VolltunnelEnabled(),
		Forwarding: core.IPv4Forwarding(),
	}
	resp.Command = []string{"nft", "list", "table", "ip", volltunnelTable}
	route := core.DefaultRoute(ctx)
	resp.PublicIf = route.Dev
	if _, err := core.ReadAdminFile(configPath); errors.Is(err, fs.ErrNotExist) {
		resp.Mocked = true
		resp.Detail = err.Error()
		return resp
	}
	if role, _ := CurrentRole(); role.Role != RoleHub {
		resp.Detail = "Volltunnel nur auf dem Hub"
		return resp
	}
	resp.TableLive = core.RunAdminQuiet(ctx, "nft", "list", "table", "ip", volltunnelTable).Err == nil
	resp.Unit = strings.TrimSpace(core.Run(ctx, "systemctl", "is-enabled", volltunnelUnit).Stdout)
	return resp
}
