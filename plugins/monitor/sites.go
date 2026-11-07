package monitor

import (
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"

	"godebplay/backend/agent"
	"godebplay/backend/core"
	"godebplay/backend/metrics"
	"godebplay/plugins/wireguard"
)

// A hub shows the health of its sites (the home VM). It asks each site over
// the tunnel for a short summary; the site answers only requests from the
// hub's tunnel address. WireGuard binds that source address to the hub's
// key, and phones behind the same hub have addresses of their own, so
// nobody else gets an answer (the route is public for the session check,
// see auth.protected).

func init() {
	// GoDeb Play is always a site: it answers its hub, it never polls sites.
	extraRoutes = append(extraRoutes, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/plugins/monitor/site", handleSite)
	})
}

// SiteGame is a game server of a site.
type SiteGame struct {
	ID      string  `json:"id"`
	Up      bool    `json:"up"`
	Players float64 `json:"players"`
	Slots   float64 `json:"slots"`
}

// SiteStatus is what a site tells its hub.
type SiteStatus struct {
	Host     string             `json:"host"`
	Time     int64              `json:"time"`
	Status   metrics.Status     `json:"status"`
	Findings []metrics.Finding  `json:"findings"`
	Values   map[string]float64 `json:"values"`
	Games    []SiteGame         `json:"games"`
	Uptime   float64            `json:"uptime"`
}

// siteValues are the numbers a site shares.
var siteValues = []string{"cpu", "mem", "load1", "wg.online"}

// BuildSiteStatus condenses a snapshot for the hub.
func BuildSiteStatus(snap metrics.Snapshot, host string, uptime float64) SiteStatus {
	st := SiteStatus{Host: host, Time: snap.Time, Status: snap.Status, Findings: []metrics.Finding{}, Values: map[string]float64{}, Games: []SiteGame{}, Uptime: uptime}
	for _, f := range snap.Findings {
		if f.Status != metrics.StatusInfo {
			st.Findings = append(st.Findings, metrics.Finding{ID: f.ID, Status: f.Status, Title: f.Title})
		}
	}
	games := map[string]*SiteGame{}
	diskMax := -1.0
	for _, s := range snap.Series {
		for _, n := range siteValues {
			if s.Name == n {
				st.Values[n] = s.Value
			}
		}
		if strings.HasPrefix(s.Name, "disk:") && s.Value > diskMax {
			diskMax = s.Value
		}
		if rest, ok := strings.CutPrefix(s.Name, "game:"); ok {
			id, field, ok := strings.Cut(rest, ":")
			if !ok {
				continue
			}
			g := games[id]
			if g == nil {
				g = &SiteGame{ID: id}
				games[id] = g
			}
			switch field {
			case "up":
				g.Up = s.Value == 1
			case "players":
				g.Players = s.Value
			case "slots":
				g.Slots = s.Value
			}
		}
	}
	if diskMax >= 0 {
		st.Values["disk"] = diskMax
	}
	for _, g := range games {
		st.Games = append(st.Games, *g)
	}
	sort.Slice(st.Games, func(i, j int) bool { return st.Games[i].ID < st.Games[j].ID })
	return st
}

// requester is the browser or hub address as seen by the web process.
func requester(r *http.Request) string {
	if ip := agent.ClientIP(r); ip != "" {
		return ip
	}
	return core.ClientIP(r)
}

func handleSite(w http.ResponseWriter, r *http.Request) {
	hub, ok := wireguard.HubTunnelAddr()
	from, err := netip.ParseAddr(requester(r))
	if !ok || err != nil || from.Unmap() != hub {
		http.NotFound(w, r)
		return
	}
	c, _, ok := current()
	if !ok {
		unavailable(w)
		return
	}
	host, _ := os.Hostname()
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, BuildSiteStatus(c.Snapshot(), host, readHost().Uptime))
}
