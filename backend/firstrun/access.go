package firstrun

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"

	"godebplay/backend/core"
)

// Access modes for the web UI. Plain HTTP stays on loopback and wg0 in every
// mode; "lan" adds HTTPS on one LAN address, never on a public one.
const (
	AccessTunnel = "tunnel" // loopback + wg0 only
	AccessLAN    = "lan"    // plus HTTPS on the LAN address
	AccessLocal  = "local"  // loopback only (SSH port forwarding)
)

// DefaultLANPort is the HTTPS port in the home network.
const DefaultLANPort = 8443

// AccessConfig is /etc/godeb-play/access.json.
type AccessConfig struct {
	Mode    string `json:"mode"`
	Address string `json:"address,omitempty"`
	Iface   string `json:"iface,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	Port    int    `json:"port,omitempty"`
}

// LoadAccess reads the access mode; without a file it is tunnel-only.
func LoadAccess() AccessConfig {
	data, err := os.ReadFile(accessPath())
	if err != nil {
		return AccessConfig{Mode: AccessTunnel}
	}
	var c AccessConfig
	if json.Unmarshal(data, &c) != nil || c.Mode == "" {
		return AccessConfig{Mode: AccessTunnel}
	}
	return c
}

// Addr is the LAN HTTPS address, or "" when LAN access is off.
func (c AccessConfig) Addr() string {
	if c.Mode != AccessLAN || c.Address == "" {
		return ""
	}
	return net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
}

// ResolveAccess validates a requested mode. For LAN access the address must
// be a private IPv4 address of this host.
func ResolveAccess(mode, address string, port int) (AccessConfig, error) {
	switch mode {
	case AccessTunnel, AccessLocal:
		return AccessConfig{Mode: mode}, nil
	case AccessLAN:
	default:
		return AccessConfig{}, fmt.Errorf("Unbekannte Erreichbarkeit %q", mode)
	}
	if port == 0 {
		port = DefaultLANPort
	}
	if port < 1024 || port > 65535 || port == 8080 {
		return AccessConfig{}, fmt.Errorf("Port muss zwischen 1024 und 65535 liegen und darf nicht 8080 sein")
	}
	for _, a := range core.LANAddresses() {
		if a.Address == address {
			return AccessConfig{Mode: AccessLAN, Address: a.Address, Iface: a.Iface, Prefix: a.Prefix, Port: port}, nil
		}
	}
	return AccessConfig{}, fmt.Errorf("%s ist keine private LAN-Adresse dieses Servers", address)
}

// SaveAccess stores the mode; the daemon opens or closes the LAN listener.
func SaveAccess(c AccessConfig) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(accessPath(), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	notify()
	return nil
}
