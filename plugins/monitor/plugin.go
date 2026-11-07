// Package monitor is the "Überwachung" plugin: health light, live values,
// history charts and events of this host. The collector (backend/metrics)
// runs as a service of this plugin inside the root agent.
package monitor

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
	"godebplay/backend/pluginmgr"
)

func init() {
	core.Register("monitor", Mount)
	core.RegisterService("monitor", run)
}

var (
	mu        sync.RWMutex
	collector *metrics.Collector
	store     *metrics.Store
	startErr  string
)

// Mount registers the monitor routes.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/monitor/summary", handleSummary)
	mux.HandleFunc("GET /api/plugins/monitor/series", handleSeries)
	mux.HandleFunc("GET /api/plugins/monitor/events", handleEvents)
	mountExtra(mux)
}

// mountExtra is filled by the other files of the plugin (network, access,
// games, alerts) so Mount stays the single entry point.
var extraRoutes []func(*http.ServeMux)

func mountExtra(mux *http.ServeMux) {
	for _, m := range extraRoutes {
		m(mux)
	}
}

func run(ctx context.Context) {
	s, err := metrics.OpenStore(metrics.Path())
	if err != nil {
		slog.Error("Überwachung: Messwert-Datenbank nicht verfügbar", "pfad", metrics.Path(), "fehler", err)
		mu.Lock()
		startErr = err.Error()
		mu.Unlock()
		return
	}
	defer s.Close()
	c := &metrics.Collector{
		Store:       s,
		Enabled:     func() bool { return !pluginmgr.IsDisabled("monitor") },
		FindingHook: findingHook,
	}
	mu.Lock()
	collector, store = c, s
	mu.Unlock()
	slog.Info("Überwachung gestartet", "pfad", metrics.Path(), "intervall", metrics.Interval)
	startServices(ctx, c, s)
	c.Run(ctx)
}

// startServices is filled by the other files (alerts, baseline).
var extraServices []func(ctx context.Context, c *metrics.Collector, s *metrics.Store)

func startServices(ctx context.Context, c *metrics.Collector, s *metrics.Store) {
	for _, f := range extraServices {
		go f(ctx, c, s)
	}
}

// findingHook is replaced by the alert code.
var findingHook = func(old, new *metrics.Finding) {}

func current() (*metrics.Collector, *metrics.Store, bool) {
	mu.RLock()
	defer mu.RUnlock()
	return collector, store, collector != nil
}

func unavailable(w http.ResponseWriter) {
	mu.RLock()
	msg := startErr
	mu.RUnlock()
	if msg == "" {
		msg = "Die Überwachung startet noch."
	} else {
		msg = "Messwert-Datenbank nicht verfügbar: " + msg
	}
	core.WriteError(w, http.StatusServiceUnavailable, msg)
}

type hostInfo struct {
	Uptime   float64 `json:"uptime"` // seconds
	Cores    int     `json:"cores"`
	MemTotal uint64  `json:"memTotal"`
}

type summaryResponse struct {
	metrics.Snapshot
	Host     hostInfo `json:"host"`
	Interval int      `json:"interval"`
}

func handleSummary(w http.ResponseWriter, r *http.Request) {
	c, _, ok := current()
	if !ok {
		unavailable(w)
		return
	}
	core.WriteJSON(w, http.StatusOK, summaryResponse{Snapshot: c.Snapshot(), Host: readHost(), Interval: int(metrics.Interval / time.Second)})
}

func readHost() hostInfo {
	h := hostInfo{Cores: runtime.NumCPU()}
	if raw, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 0 {
			h.Uptime, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.ParseUint(f[1], 10, 64)
				h.MemTotal = kb * 1024
			}
		}
	}
	return h
}

// ranges are the selectable chart windows.
var ranges = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
	"1y":  365 * 24 * time.Hour,
}

const maxSeriesPerRequest = 24

// ParseRange returns from/to for a range name.
func ParseRange(name string) (from, to int64, ok bool) {
	if name == "" {
		name = "24h"
	}
	d, ok := ranges[name]
	if !ok {
		return 0, 0, false
	}
	now := time.Now().Unix()
	return now - int64(d/time.Second), now, true
}

// ParseNames splits and validates the names parameter.
func ParseNames(raw string) ([]string, bool) {
	var out []string
	for _, n := range strings.Split(raw, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !metrics.ValidSeriesPattern(n) {
			return nil, false
		}
		out = append(out, n)
	}
	if len(out) == 0 || len(out) > maxSeriesPerRequest {
		return nil, false
	}
	return out, true
}

func handleSeries(w http.ResponseWriter, r *http.Request) {
	_, s, ok := current()
	if !ok {
		unavailable(w)
		return
	}
	names, ok := ParseNames(r.URL.Query().Get("names"))
	if !ok {
		core.WriteError(w, http.StatusBadRequest, "Ungültige Messreihen")
		return
	}
	from, to, ok := ParseRange(r.URL.Query().Get("range"))
	if !ok {
		core.WriteError(w, http.StatusBadRequest, "Ungültiger Zeitraum")
		return
	}
	res, err := s.Query(r.Context(), names, from, to)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Messwerte nicht lesbar")
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	_, s, ok := current()
	if !ok {
		unavailable(w)
		return
	}
	from, to, ok := ParseRange(r.URL.Query().Get("range"))
	if !ok {
		core.WriteError(w, http.StatusBadRequest, "Ungültiger Zeitraum")
		return
	}
	events, err := s.Events(r.Context(), from, to, 500)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Ereignisse nicht lesbar")
		return
	}
	if events == nil {
		events = []metrics.Event{}
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"events": events})
}
