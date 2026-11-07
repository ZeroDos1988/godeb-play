package wireguard

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/core"
)

const clientsDir = "/etc/wireguard/clients"

var (
	clientName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	hostName   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)
)

// Client is the public view of /etc/wireguard/clients/<name>.conf.
type Client struct {
	Name           string   `json:"name"`
	PublicKey      string   `json:"publicKey"`
	Created        string   `json:"created,omitempty"`
	Addresses      []string `json:"addresses"`
	DNS            []string `json:"dns"`
	Endpoint       string   `json:"endpoint,omitempty"`
	AllowedIPs     []string `json:"allowedIPs"`
	AllowedIPsBase []string `json:"allowedIPsBase,omitempty"`
	ExcludedIPs    []string `json:"excludedIPs,omitempty"`
	// Site marks a GoDeb host behind the hub (the home VM), see CreatePeer.
	Site bool `json:"site,omitempty"`
}

// ClientSpec holds everything needed to render a client configuration.
type ClientSpec struct {
	Name           string
	Keys           Keypair
	PresharedKey   string
	Address        netip.Addr
	DNS            []string
	ServerKey      string
	Endpoint       string
	AllowedIPs     []string
	AllowedIPsBase []string
	ExcludedIPs    []string
	Keepalive      int
	Created        time.Time
	Site           bool
}

func clientPath(name string) string {
	return filepath.Join(clientsDir, name+".conf")
}

// RenderClient produces a wg-quick configuration for the client device. The
// leading comments let GoDeb list clients without deriving keys again.
func RenderClient(s ClientSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# GoDeb-Client: %s\n", s.Name)
	fmt.Fprintf(&b, "# GoDeb-PublicKey: %s\n", s.Keys.Public)
	fmt.Fprintf(&b, "# GoDeb-Created: %s\n", s.Created.UTC().Format(time.RFC3339))
	if len(s.AllowedIPsBase) > 0 {
		fmt.Fprintf(&b, "# GoDeb-AllowedIPs-Base: %s\n", strings.Join(s.AllowedIPsBase, ", "))
	}
	if len(s.ExcludedIPs) > 0 {
		fmt.Fprintf(&b, "# GoDeb-ExcludedIPs: %s\n", strings.Join(s.ExcludedIPs, ", "))
	}
	if s.Site {
		fmt.Fprintf(&b, "# %s: %s\n", roleMarker, siteRole)
	}
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", s.Keys.Private)
	fmt.Fprintf(&b, "Address = %s/32\n", s.Address)
	if len(s.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(s.DNS, ", "))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", s.ServerKey)
	if s.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", s.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", s.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(s.AllowedIPs, ", "))
	if s.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", s.Keepalive)
	}
	return b.String()
}

// RenderServerPeer is the [Peer] block appended to wg0.conf.
func RenderServerPeer(name, publicKey, presharedKey string, address netip.Addr) string {
	var b strings.Builder
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "# Name = %s\n", name)
	fmt.Fprintf(&b, "PublicKey = %s\n", publicKey)
	if presharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", presharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s/32\n", address)
	return b.String()
}

// ParseClient reads a client file without exposing its private or preshared key.
func ParseClient(name, content string) Client {
	cfg := ParseConfig(content)
	c := Client{
		Name:       name,
		Addresses:  cfg.Interface.Addresses,
		DNS:        cfg.Interface.DNS,
		AllowedIPs: []string{},
	}
	if len(cfg.Peers) > 0 {
		c.Endpoint = cfg.Peers[0].Endpoint
		c.AllowedIPs = cfg.Peers[0].AllowedIPs
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := commentValue(line, "GoDeb-PublicKey"); ok {
			c.PublicKey = v
		} else if v, ok := commentValue(line, "GoDeb-Created"); ok {
			c.Created = v
		} else if v, ok := commentValue(line, "GoDeb-AllowedIPs-Base"); ok {
			c.AllowedIPsBase = splitList(v)
		} else if v, ok := commentValue(line, "GoDeb-ExcludedIPs"); ok {
			c.ExcludedIPs = splitList(v)
		} else if v, ok := commentValue(line, roleMarker); ok {
			c.Site = v == siteRole
		}
	}
	return c
}

// LoadClients reads every *.conf under /etc/wireguard/clients. A missing
// directory yields an empty list.
func LoadClients() ([]Client, error) {
	names, err := core.ListAdminDir(clientsDir)
	if err != nil {
		return []Client{}, err
	}
	clients := make([]Client, 0, len(names))
	for _, file := range names {
		name, ok := strings.CutSuffix(file, ".conf")
		if !ok || !clientName.MatchString(name) {
			continue
		}
		data, err := core.ReadAdminFile(clientPath(name))
		if err != nil {
			continue
		}
		clients = append(clients, ParseClient(name, string(data)))
	}
	return clients, nil
}

// NextFreeIP returns the first host address in the server's IPv4 subnet that
// is neither the server itself nor listed in used.
func NextFreeIP(serverAddrs, used []string) (netip.Addr, error) {
	prefix, server, err := serverPrefix(serverAddrs)
	if err != nil {
		return netip.Addr{}, err
	}
	taken := map[netip.Addr]bool{server: true}
	for _, entry := range used {
		if addr, ok := hostAddr(entry); ok {
			taken[addr] = true
		}
	}
	network := prefix.Masked().Addr()
	for addr := network.Next(); prefix.Contains(addr); addr = addr.Next() {
		if !prefix.Contains(addr.Next()) {
			break
		}
		if !taken[addr] {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("keine freie Adresse in %s", prefix.Masked())
}

// checkAddress validates a requested client address against the subnet.
func checkAddress(raw string, serverAddrs, used []string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("Adresse muss eine IPv4-Adresse sein")
	}
	prefix, server, err := serverPrefix(serverAddrs)
	if err != nil {
		return netip.Addr{}, err
	}
	network := prefix.Masked().Addr()
	if !prefix.Contains(addr) || addr == network || addr == server {
		return netip.Addr{}, fmt.Errorf("Adresse %s liegt nicht frei in %s", addr, prefix.Masked())
	}
	for _, entry := range used {
		if taken, ok := hostAddr(entry); ok && taken == addr {
			return netip.Addr{}, fmt.Errorf("Adresse %s ist bereits vergeben", addr)
		}
	}
	return addr, nil
}

// clientAddress picks the tunnel address of a new peer. The host right after
// the hub (10.8.0.2) is meant for the first site, the address the guides and
// the port forwarding template use: sites take it when free, devices leave
// it alone until a site exists or nothing else is free.
func clientAddress(req PeerRequest, serverAddrs, used []string, haveSite bool) (netip.Addr, error) {
	if strings.TrimSpace(req.Address) != "" {
		return checkAddress(req.Address, serverAddrs, used)
	}
	preferred, err := siteAddress(serverAddrs, used)
	switch {
	case err != nil:
	case req.Site:
		return preferred, nil
	case !haveSite:
		if addr, err := NextFreeIP(serverAddrs, append(used[:len(used):len(used)], preferred.String())); err == nil {
			return addr, nil
		}
	}
	return NextFreeIP(serverAddrs, used)
}

// siteAddress returns the host right after the hub address if it is free.
func siteAddress(serverAddrs, used []string) (netip.Addr, error) {
	_, server, err := serverPrefix(serverAddrs)
	if err != nil {
		return netip.Addr{}, err
	}
	return checkAddress(server.Next().String(), serverAddrs, used)
}

func serverPrefix(serverAddrs []string) (netip.Prefix, netip.Addr, error) {
	for _, raw := range serverAddrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil && prefix.Addr().Is4() && prefix.Bits() < 31 {
			return prefix, prefix.Addr(), nil
		}
	}
	return netip.Prefix{}, netip.Addr{}, fmt.Errorf("wg0.conf enthält keine IPv4-Adresse mit Subnetz")
}

func hostAddr(entry string) (netip.Addr, bool) {
	entry = strings.TrimSpace(entry)
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		if prefix.IsSingleIP() {
			return prefix.Addr(), true
		}
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(entry)
	return addr, err == nil
}

func validEndpoint(raw string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("Endpoint muss host:port sein")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("Endpoint-Port ist ungültig")
	}
	if _, err := netip.ParseAddr(host); err != nil && !hostName.MatchString(host) {
		return "", fmt.Errorf("Endpoint-Host ist ungültig")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func validDNS(raw string) ([]string, error) {
	out := []string{}
	for _, part := range splitList(raw) {
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("DNS-Eintrag %q ist keine IP-Adresse", part)
		}
		out = append(out, addr.String())
	}
	return out, nil
}

func validAllowedIPs(raw string) ([]string, error) {
	out := []string{}
	for _, part := range splitList(raw) {
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("AllowedIPs-Eintrag %q ist kein Netz", part)
		}
		out = append(out, prefix.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("AllowedIPs darf nicht leer sein")
	}
	return out, nil
}
