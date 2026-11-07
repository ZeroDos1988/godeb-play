package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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

const (
	sitePort     = 8080 // GoDeb listens on a site's wg0 (GODEB_ADDR default)
	sitePoll     = time.Minute
	siteTimeout  = 5 * time.Second
	siteStale    = 3 * time.Minute
	maxSiteBytes = 64 << 10
)

func init() {
	extraRoutes = append(extraRoutes, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/plugins/monitor/site", handleSite)
		mux.HandleFunc("GET /api/plugins/monitor/sites", handleSites)
	})
	extraServices = append(extraServices, runSites)
	metrics.RegisterSource("sites", siteSource)
	metrics.RegisterCheck("sites", siteCheck)
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

// SiteView is a site as the hub sees it.
type SiteView struct {
	Name      string      `json:"name"`
	Address   string      `json:"address"`
	Reachable bool        `json:"reachable"`
	LastSeen  int64       `json:"lastSeen"`
	Error     string      `json:"error,omitempty"`
	Status    *SiteStatus `json:"status,omitempty"`
}

var (
	sitesMu sync.Mutex
	sites   = map[string]*SiteView{}
)

func siteList() []SiteView {
	sitesMu.Lock()
	defer sitesMu.Unlock()
	out := make([]SiteView, 0, len(sites))
	for _, s := range sites {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func handleSites(w http.ResponseWriter, r *http.Request) {
	role, _ := wireguard.CurrentRole()
	core.WriteJSON(w, http.StatusOK, map[string]any{"hub": role.Role == wireguard.RoleHub, "sites": siteList()})
}

var siteClient = &http.Client{
	Timeout:       siteTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func fetchSite(ctx context.Context, addr string) (*SiteStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(addr, strconv.Itoa(sitePort))+"/api/plugins/monitor/site", nil)
	if err != nil {
		return nil, err
	}
	resp, err := siteClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d (Überwachung auf dem Standort aus oder älteres GoDeb)", resp.StatusCode)
	}
	var st SiteStatus
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxSiteBytes)).Decode(&st); err != nil {
		return nil, fmt.Errorf("Antwort unlesbar: %w", err)
	}
	return sanitizeSite(st), nil
}

// sanitizeSite bounds what a site sends: it is another host, its answer
// is data, not trusted input.
func sanitizeSite(st SiteStatus) *SiteStatus {
	clip := func(s string, n int) string {
		if len(s) > n {
			return s[:n]
		}
		return s
	}
	st.Host = clip(st.Host, 64)
	switch st.Status {
	case metrics.StatusOK, metrics.StatusInfo, metrics.StatusWarning, metrics.StatusCritical:
	default:
		st.Status = metrics.StatusWarning
	}
	if len(st.Findings) > 20 {
		st.Findings = st.Findings[:20]
	}
	for i := range st.Findings {
		f := &st.Findings[i]
		f.ID, f.Title, f.Detail = clip(f.ID, 80), clip(f.Title, 160), ""
		if f.Status != metrics.StatusCritical {
			f.Status = metrics.StatusWarning
		}
	}
	vals := map[string]float64{}
	for _, k := range append(siteValues, "disk") {
		if v, ok := st.Values[k]; ok {
			vals[k] = v
		}
	}
	st.Values = vals
	var games []SiteGame
	for _, g := range st.Games {
		if len(games) < 8 && metrics.ValidSeriesPattern("game:"+g.ID+":up") {
			games = append(games, g)
		}
	}
	st.Games = games
	return &st
}

func runSites(ctx context.Context, _ *metrics.Collector, _ *metrics.Store) {
	t := time.NewTicker(sitePoll)
	defer t.Stop()
	for {
		pollSites(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func pollSites(ctx context.Context) {
	role, err := wireguard.CurrentRole()
	if err != nil || role.Role != wireguard.RoleHub {
		sitesMu.Lock()
		sites = map[string]*SiteView{}
		sitesMu.Unlock()
		return
	}
	list, err := wireguard.Sites()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, c := range list {
		addr := ""
		for _, a := range c.Addresses {
			if p, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil && p.Addr().Is4() {
				addr = p.Addr().String()
				break
			}
		}
		name := metrics.SeriesPart(c.Name)
		if addr == "" || name == "" {
			continue
		}
		seen[name] = true
		st, err := fetchSite(ctx, addr)
		sitesMu.Lock()
		v := sites[name]
		if v == nil {
			v = &SiteView{Name: c.Name, Address: addr}
			sites[name] = v
		}
		if err != nil {
			v.Reachable, v.Error = false, err.Error()
		} else {
			v.Reachable, v.Error, v.Status, v.LastSeen = true, "", st, time.Now().Unix()
		}
		sitesMu.Unlock()
	}
	sitesMu.Lock()
	for k := range sites {
		if !seen[k] {
			delete(sites, k)
		}
	}
	sitesMu.Unlock()
}

func siteSource(ctx context.Context) []metrics.Sample {
	var out []metrics.Sample
	for _, s := range siteList() {
		name := metrics.SeriesPart(s.Name)
		up := 0.0
		if s.Reachable {
			up = 1
		}
		out = append(out, metrics.Sample{Series: "site:" + name + ":up", Value: up, Label: s.Name})
		if !s.Reachable || s.Status == nil {
			continue
		}
		for k, v := range s.Status.Values {
			out = append(out, metrics.Sample{Series: "site:" + name + ":" + k, Value: v, Label: s.Name})
		}
		for _, g := range s.Status.Games {
			out = append(out, metrics.Sample{Series: "site:" + name + ":game:" + g.ID + ":players", Value: g.Players, Label: s.Name + " " + g.ID})
		}
	}
	return out
}

// siteCheck mirrors the problems of each site into the hub's light, so
// alerts on the hub cover the home VM as well.
func siteCheck(ctx context.Context) []metrics.Finding {
	var out []metrics.Finding
	now := time.Now().Unix()
	for _, s := range siteList() {
		name := metrics.SeriesPart(s.Name)
		if !s.Reachable && (s.LastSeen == 0 || now-s.LastSeen > int64(siteStale/time.Second)) {
			out = append(out, metrics.Finding{ID: "site:" + name, Status: metrics.StatusCritical, Title: "Standort nicht erreichbar: " + s.Name, Detail: s.Error})
			continue
		}
		if s.Status == nil {
			continue
		}
		for _, f := range s.Status.Findings {
			out = append(out, metrics.Finding{ID: "site:" + name + ":" + f.ID, Status: f.Status, Title: s.Name + ": " + f.Title})
		}
	}
	return out
}
