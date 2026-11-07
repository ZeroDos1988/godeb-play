package monitor

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
)

// The baseline answers "is this normal for now?": the median of the hourly
// averages at the same hour of the week over the last four weeks, or, while
// there is less history, the same hour of the day over the last week.
// Only unusually HIGH values are reported; quiet is never a problem.

const (
	baselineWeeks   = 4
	baselineRefresh = 15 * time.Minute
	anomalyWindow   = 15 * time.Minute
	maxAnomalySet   = 40
)

func init() {
	extraRoutes = append(extraRoutes, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/plugins/monitor/baseline", handleBaseline)
	})
	metrics.RegisterCheck("anomaly", anomalyCheck)
}

// Profile is the typical value per hour of the week (0 = Sunday 00:00
// local time) and per hour of the day as fallback.
type Profile struct {
	week [168][]float64
	day  [24][]float64
}

// BuildProfile sorts hourly averages into hour-of-week and hour-of-day buckets.
func BuildProfile(points []metrics.Point, now time.Time) *Profile {
	p := &Profile{}
	dayCut := now.Add(-7 * 24 * time.Hour).Unix()
	for _, pt := range points {
		t := time.Unix(int64(pt[0]), 0).In(now.Location())
		p.week[int(t.Weekday())*24+t.Hour()] = append(p.week[int(t.Weekday())*24+t.Hour()], pt[1])
		if int64(pt[0]) >= dayCut {
			p.day[t.Hour()] = append(p.day[t.Hour()], pt[1])
		}
	}
	return p
}

// Expected returns the typical value at t, false while there is too little
// history (two weeks for the weekly profile, three days for the daily one).
func (p *Profile) Expected(t time.Time) (float64, bool) {
	if w := p.week[int(t.Weekday())*24+t.Hour()]; len(w) >= 2 {
		return median(w), true
	}
	if d := p.day[t.Hour()]; len(d) >= 3 {
		return median(d), true
	}
	return 0, false
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

var (
	profMu   sync.Mutex
	profiles = map[string]*Profile{}
	profAt   = map[string]time.Time{}
)

func profile(ctx context.Context, s *metrics.Store, series string) (*Profile, error) {
	profMu.Lock()
	defer profMu.Unlock()
	if p, ok := profiles[series]; ok && time.Since(profAt[series]) < baselineRefresh {
		return p, nil
	}
	now := time.Now()
	hist, err := s.HourlyHistory(ctx, series, now.Add(-baselineWeeks*7*24*time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	p := BuildProfile(hist, now)
	profiles[series], profAt[series] = p, now
	return p, nil
}

// Judge rates a current value against the expected one. Thresholds depend
// on the unit so that tiny absolute changes never alarm.
func Judge(unit string, current, expected float64) (metrics.Status, bool) {
	switch unit {
	case "B/s":
		delta := current - expected
		switch {
		case current >= 10*expected && delta >= 1e6:
			return metrics.StatusWarning, true
		case current >= 3*expected && delta >= 100e3:
			return metrics.StatusInfo, true
		}
	case "%":
		switch {
		case current-expected >= 50:
			return metrics.StatusWarning, true
		case current-expected >= 30 && current >= 2*expected:
			return metrics.StatusInfo, true
		}
	}
	return metrics.StatusOK, false
}

// anomalyCandidates are the series worth judging: CPU, interfaces, services.
func anomalyCandidates(c *metrics.Collector) []metrics.SeriesInfo {
	var out []metrics.SeriesInfo
	for _, s := range c.Snapshot().Series {
		if s.Name == "cpu" || strings.HasPrefix(s.Name, "net:") || strings.HasPrefix(s.Name, "svc:") {
			out = append(out, s)
		}
		if len(out) >= maxAnomalySet {
			break
		}
	}
	return out
}

func anomalyCheck(ctx context.Context) []metrics.Finding {
	c, s, ok := current()
	if !ok {
		return nil
	}
	now := time.Now()
	var out []metrics.Finding
	for _, info := range anomalyCandidates(c) {
		p, err := profile(ctx, s, info.Name)
		if err != nil {
			continue
		}
		expected, ok := p.Expected(now)
		if !ok {
			continue
		}
		r, err := s.Query(ctx, []string{info.Name}, now.Add(-anomalyWindow).Unix(), now.Unix())
		if err != nil || len(r.Series[info.Name]) == 0 {
			continue
		}
		sum := 0.0
		for _, pt := range r.Series[info.Name] {
			sum += pt[1]
		}
		cur := sum / float64(len(r.Series[info.Name]))
		status, unusual := Judge(info.Unit, cur, expected)
		if !unusual {
			continue
		}
		out = append(out, metrics.Finding{
			ID:     "anomaly:" + info.Name,
			Status: status,
			Title:  "Ungewöhnlich hoch: " + anomalyLabel(info),
			Detail: fmt.Sprintf("seit 15 Minuten im Mittel %s, üblich um diese Zeit %s", formatUnit(cur, info.Unit), formatUnit(expected, info.Unit)),
		})
	}
	return out
}

func anomalyLabel(s metrics.SeriesInfo) string {
	switch {
	case s.Name == "cpu":
		return "CPU-Last"
	case strings.HasSuffix(s.Name, ":rx") || strings.HasSuffix(s.Name, ":in"):
		return s.Label + " (eingehend)"
	case strings.HasSuffix(s.Name, ":tx") || strings.HasSuffix(s.Name, ":out"):
		return s.Label + " (ausgehend)"
	}
	return s.Label
}

func formatUnit(v float64, unit string) string {
	switch unit {
	case "%":
		return fmt.Sprintf("%.0f %%", v)
	case "B/s":
		units := []string{"B/s", "KB/s", "MB/s", "GB/s"}
		i := 0
		for v >= 1000 && i < len(units)-1 {
			v /= 1000
			i++
		}
		return fmt.Sprintf("%.1f %s", v, units[i])
	}
	return fmt.Sprintf("%.1f", v)
}

// handleBaseline returns the typical value per hour for the requested
// series and range, for the dashed "usual" line in the charts.
func handleBaseline(w http.ResponseWriter, r *http.Request) {
	_, s, ok := current()
	if !ok {
		unavailable(w)
		return
	}
	names, ok := ParseNames(r.URL.Query().Get("names"))
	if !ok || len(names) > 8 {
		core.WriteError(w, http.StatusBadRequest, "Ungültige Messreihen")
		return
	}
	for _, n := range names {
		if strings.HasSuffix(n, "*") {
			core.WriteError(w, http.StatusBadRequest, "Grundlinie nur für einzelne Messreihen")
			return
		}
	}
	from, to, ok := ParseRange(r.URL.Query().Get("range"))
	if !ok || to-from > 7*24*3600 {
		core.WriteError(w, http.StatusBadRequest, "Grundlinie nur bis 7 Tage")
		return
	}
	out := map[string][]metrics.Point{}
	for _, n := range names {
		p, err := profile(r.Context(), s, n)
		if err != nil {
			core.WriteError(w, http.StatusInternalServerError, "Messwerte nicht lesbar")
			return
		}
		var pts []metrics.Point
		for t := from / 3600 * 3600; t <= to; t += 3600 {
			if v, ok := p.Expected(time.Unix(t, 0)); ok {
				pts = append(pts, metrics.Point{float64(t), v, v})
			}
		}
		out[n] = pts
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"series": out})
}
