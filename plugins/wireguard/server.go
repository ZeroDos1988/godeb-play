package wireguard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"strings"

	"godebplay/backend/core"
)

// ServerSpec describes a new wg0 interface created by `godeb-play setup`.
type ServerSpec struct {
	Address    netip.Prefix
	ListenPort int
}

// ConfigPath is the server configuration GoDeb manages.
func ConfigPath() string { return configPath }

// ServerConfigured reports whether wg0.conf already exists.
func ServerConfigured() (bool, error) {
	_, err := core.ReadAdminFile(configPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// InitServer writes a fresh wg0.conf with a new key. An existing file is
// never touched; the caller checks ServerConfigured first.
func InitServer(ctx context.Context, spec ServerSpec) (publicKey string, err error) {
	if !spec.Address.Addr().Is4() || spec.Address.Bits() < 16 || spec.Address.Bits() > 30 {
		return "", fmt.Errorf("Tunnel-Adresse muss IPv4 mit /16 bis /30 sein")
	}
	if spec.Address.Addr() == spec.Address.Masked().Addr() {
		return "", fmt.Errorf("Tunnel-Adresse %s ist die Netzadresse", spec.Address)
	}
	if spec.ListenPort < 1024 || spec.ListenPort > 65535 {
		return "", fmt.Errorf("ListenPort muss zwischen 1024 und 65535 liegen")
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	if ok, err := ServerConfigured(); err != nil || ok {
		if err == nil {
			err = fmt.Errorf("%s existiert bereits", configPath)
		}
		return "", err
	}
	keys, err := GenerateKeypair(ctx)
	if err != nil {
		return "", err
	}
	if err := core.WriteAdminFile(configPath, []byte(RenderServer(spec, keys.Private)), 0o600); err != nil {
		return "", err
	}
	return keys.Public, nil
}

// RenderServer produces the [Interface] section of wg0.conf. Clients only
// reach the tunnel network itself, so no forwarding or NAT rules are needed.
func RenderServer(spec ServerSpec, privateKey string) string {
	var b strings.Builder
	b.WriteString("# Managed by GoDeb. Peers are appended by the web UI.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", spec.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", spec.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	return b.String()
}
