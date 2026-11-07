package wireguard

import "strings"

// Interface is the [Interface] section without secrets.
type Interface struct {
	Addresses  []string `json:"addresses"`
	ListenPort string   `json:"listenPort,omitempty"`
	DNS        []string `json:"dns"`
}

// Peer is one [Peer] section without preshared keys. Name comes from a
// "# Name = ..." comment inside the section, which wg-quick ignores.
type Peer struct {
	Name       string   `json:"name,omitempty"`
	PublicKey  string   `json:"publicKey,omitempty"`
	AllowedIPs []string `json:"allowedIPs"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

// Config is the public view of a WireGuard configuration.
type Config struct {
	Interface Interface `json:"interface"`
	Peers     []Peer    `json:"peers"`
	Redacted  []string  `json:"redacted"`
}

const sampleConfig = `[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = not-a-real-key
DNS = 1.1.1.1

[Peer]
# Name = laptop
PublicKey = example-peer-public-key
AllowedIPs = 10.8.0.2/32
Endpoint = 203.0.113.10:51820
`

// ParseConfig reads wg0.conf and drops private and preshared keys.
func ParseConfig(content string) Config {
	cfg := Config{
		Interface: Interface{Addresses: []string{}, DNS: []string{}},
		Peers:     []Peer{},
		Redacted:  []string{},
	}
	section := ""
	var peer *Peer
	seen := map[string]bool{}
	flush := func() {
		if peer == nil {
			return
		}
		cfg.Peers = append(cfg.Peers, *peer)
		peer = nil
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			if name, ok := commentValue(line, "Name"); ok && peer != nil {
				peer.Name = name
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section = strings.ToLower(strings.Trim(line, "[]"))
			if section == "peer" {
				peer = &Peer{AllowedIPs: []string{}}
			}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		lower := strings.ToLower(key)
		if lower == "privatekey" || lower == "presharedkey" {
			if !seen[key] {
				seen[key] = true
				cfg.Redacted = append(cfg.Redacted, key)
			}
			continue
		}
		switch section {
		case "interface":
			switch lower {
			case "address":
				cfg.Interface.Addresses = append(cfg.Interface.Addresses, splitList(val)...)
			case "listenport":
				cfg.Interface.ListenPort = val
			case "dns":
				cfg.Interface.DNS = append(cfg.Interface.DNS, splitList(val)...)
			}
		case "peer":
			if peer == nil {
				continue
			}
			switch lower {
			case "publickey":
				peer.PublicKey = val
			case "allowedips":
				peer.AllowedIPs = append(peer.AllowedIPs, splitList(val)...)
			case "endpoint":
				peer.Endpoint = val
			}
		}
	}
	flush()
	return cfg
}

// commentValue reads "# Key = value" or "# Key: value" comment lines.
func commentValue(line, key string) (string, bool) {
	body := strings.TrimSpace(strings.TrimLeft(line, "#;"))
	sep := strings.IndexAny(body, "=:")
	if sep < 0 || !strings.EqualFold(strings.TrimSpace(body[:sep]), key) {
		return "", false
	}
	return strings.TrimSpace(body[sep+1:]), true
}

// interfaceValue returns the raw value of a key in the [Interface] section,
// including secrets. It is only used server-side.
func interfaceValue(content, key string) string {
	section := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		if section != "interface" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func splitList(val string) []string {
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
