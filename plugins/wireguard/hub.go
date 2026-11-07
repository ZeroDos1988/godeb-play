package wireguard

import (
	"context"
	"net/netip"
	"strconv"

	"godebplay/backend/core"
	"godebplay/plugins/ufw"
)

const (
	// siteRole marks the client file of a GoDeb host behind the hub.
	siteRole = "site"
	// hubRouteTag owns the ufw route rules created for sites.
	hubRouteTag = "GoDeb-Hub"
	// siteUIPort is where GoDeb listens on a site's wg0 (GODEB_ADDR default).
	siteUIPort = 8080
)

// SyncHubRoutes lets tunnel clients (phone, laptop) reach the web UI of every
// site through the hub, and nothing else of the site: one
// `ufw route allow in on wg0 out on wg0 to <site> port 8080 proto tcp` per
// site. Without sites the rules are removed; forwarding stays on because
// port forwarding may still need it.
func SyncHubRoutes(ctx context.Context) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	return syncHubRoutes(ctx)
}

// syncHubRoutes is SyncHubRoutes for callers that hold writeMu.
func syncHubRoutes(ctx context.Context) error {
	clients, err := LoadClients()
	if err != nil {
		return err
	}
	rules := []ufw.RouteRule{}
	for _, c := range clients {
		if !c.Site {
			continue
		}
		for _, a := range c.Addresses {
			addr, ok := hostAddr(a)
			if !ok || !addr.Is4() {
				continue
			}
			rules = append(rules, ufw.RouteRule{
				In: iface, Out: iface, To: addr.String(),
				Port: strconv.Itoa(siteUIPort), Proto: "tcp",
				Comment: hubRouteTag + " " + c.Name,
			})
		}
	}
	if len(rules) > 0 {
		if err := core.EnableIPv4Forwarding(ctx); err != nil {
			return err
		}
	}
	return ufw.SyncRoutes(ctx, hubRouteTag, rules)
}

// Sites lists the site peers (GoDeb hosts behind this hub) with their
// tunnel address. The port forwarding plugin uses it to offer targets.
func Sites() ([]Client, error) {
	clients, err := LoadClients()
	if err != nil {
		return nil, err
	}
	return sites(clients), nil
}

func sites(clients []Client) []Client {
	out := []Client{}
	for _, c := range clients {
		if c.Site {
			out = append(out, c)
		}
	}
	return out
}

// DefaultEndpoint is the server endpoint written into an existing client
// file, so a new client gets the same public address as the others.
func DefaultEndpoint() string {
	clients, err := LoadClients()
	if err != nil {
		return ""
	}
	for _, c := range clients {
		if c.Endpoint != "" {
			return c.Endpoint
		}
	}
	return ""
}

// TunnelPrefix is the tunnel network of this hub from wg0.conf.
func TunnelPrefix() (netip.Prefix, error) {
	data, err := core.ReadAdminFile(configPath)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix, _, err := serverPrefix(ParseConfig(string(data)).Interface.Addresses)
	return prefix, err
}
