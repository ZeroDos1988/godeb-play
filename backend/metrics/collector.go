package metrics

import (
	"context"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// Interval between two samples.
const Interval = 10 * time.Second

const (
	checkInterval  = time.Minute
	rollupInterval = 5 * time.Minute
	sourceTimeout  = 5 * time.Second
	checkTimeout   = 30 * time.Second
)

// SeriesInfo describes a series for the UI.
type SeriesInfo struct {
	Name  string  `json:"name"`
	Unit  string  `json:"unit"`
	Label string  `json:"label"`
	Value float64 `json:"value"`
}

// Snapshot is the latest state: values, findings and the overall status.
type Snapshot struct {
	Time     int64        `json:"time"`
	Status   Status       `json:"status"`
	Findings []Finding    `json:"findings"`
	Series   []SeriesInfo `json:"series"`
	Checked  int64        `json:"checked"`
}

// Collector samples all sources every Interval and runs the checks every
// minute. FindingHook sees every change of a finding (for alerts).
type Collector struct {
	Store       *Store
	Enabled     func() bool
	FindingHook func(old, new *Finding)

	mu       sync.RWMutex
	prev     map[string]counterValue
	latest   map[string]SeriesInfo
	findings map[string]Finding
	checked  time.Time
	sampled  time.Time
}

type counterValue struct {
	v float64
	t time.Time
}

// Run blocks until ctx ends.
func (c *Collector) Run(ctx context.Context) {
	setSink(func(e Event) {
		if e.Time == 0 {
			e.Time = time.Now().Unix()
		}
		if err := c.Store.AddEvent(context.Background(), e); err != nil {
			slog.Warn("Ereignis nicht gespeichert", "fehler", err)
		}
		slog.Info("Ereignis", "quelle", e.Source, "stufe", string(e.Level), "text", e.Text)
	})
	defer setSink(nil)

	tick := time.NewTicker(Interval)
	defer tick.Stop()
	var lastCheck, lastRollup time.Time
	for {
		if c.Enabled == nil || c.Enabled() {
			now := time.Now()
			c.Sample(ctx, now)
			if now.Sub(lastCheck) >= checkInterval {
				c.RunChecks(ctx)
				lastCheck = now
			}
			if now.Sub(lastRollup) >= rollupInterval {
				if err := c.Store.Rollup(ctx); err != nil && ctx.Err() == nil {
					slog.Warn("Messwerte verdichten fehlgeschlagen", "fehler", err)
				}
				lastRollup = now
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Sample reads all sources once and stores the values.
func (c *Collector) Sample(ctx context.Context, now time.Time) {
	values := map[string]float64{}
	infos := map[string]SeriesInfo{}
	for _, src := range sorted(sources) {
		sctx, cancel := context.WithTimeout(ctx, sourceTimeout)
		samples := safeSource(sctx, src.name, src.fn)
		cancel()
		for _, s := range samples {
			if !validSeries(s.Series) || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
				continue
			}
			v, ok := c.value(s, now)
			if !ok {
				continue
			}
			values[s.Series] = v
			infos[s.Series] = SeriesInfo{Name: s.Series, Unit: s.Unit, Label: s.Label, Value: v}
		}
	}
	c.mu.Lock()
	c.latest = infos
	c.sampled = now
	c.mu.Unlock()
	if len(values) == 0 {
		return
	}
	if err := c.Store.Write(ctx, now.Unix(), values); err != nil && ctx.Err() == nil {
		slog.Warn("Messwerte nicht gespeichert", "fehler", err)
	}
}

// value turns a counter into a rate per second; the first reading and a
// reset (counter went down) produce no value.
func (c *Collector) value(s Sample, now time.Time) (float64, bool) {
	if !s.Counter {
		return s.Value, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prev == nil {
		c.prev = map[string]counterValue{}
	}
	prev, ok := c.prev[s.Series]
	c.prev[s.Series] = counterValue{s.Value, now}
	if !ok || s.Value < prev.v {
		return 0, false
	}
	dt := now.Sub(prev.t).Seconds()
	if dt <= 0 {
		return 0, false
	}
	return (s.Value - prev.v) / dt, true
}

// RunChecks runs all checks and reports changed findings.
func (c *Collector) RunChecks(ctx context.Context) {
	current := map[string]Finding{}
	for _, ch := range sorted(checks) {
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		for _, f := range safeCheck(cctx, ch.name, ch.fn) {
			if f.ID == "" {
				f.ID = ch.name
			}
			current[f.ID] = f
		}
		cancel()
	}
	c.mu.Lock()
	old := c.findings
	c.findings = current
	c.checked = time.Now()
	c.mu.Unlock()
	for id, f := range current {
		f := f
		if o, ok := old[id]; !ok || o.Status != f.Status {
			var op *Finding
			if ok {
				op = &o
			}
			c.report(op, &f)
		}
	}
	for id, o := range old {
		if _, ok := current[id]; !ok {
			o := o
			c.report(&o, nil)
		}
	}
}

func (c *Collector) report(old, new *Finding) {
	switch {
	case new != nil:
		Emit(Event{Source: "zustand", Level: new.Status, Text: new.Title})
	case old != nil && old.Status != StatusInfo:
		Emit(Event{Source: "zustand", Level: StatusOK, Text: "Behoben: " + old.Title})
	case old != nil:
		Emit(Event{Source: "zustand", Level: StatusOK, Text: "Vorbei: " + old.Title})
	}
	if c.FindingHook != nil {
		c.FindingHook(old, new)
	}
}

// Snapshot returns the latest values and findings.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snap := Snapshot{Time: c.sampled.Unix(), Status: StatusOK, Checked: c.checked.Unix()}
	if c.sampled.IsZero() {
		snap.Time = 0
	}
	if c.checked.IsZero() {
		snap.Checked = 0
	}
	for _, f := range c.findings {
		snap.Findings = append(snap.Findings, f)
		if Worse(f.Status, snap.Status) && f.Status != StatusInfo {
			snap.Status = f.Status
		}
	}
	sort.Slice(snap.Findings, func(i, j int) bool {
		a, b := snap.Findings[i], snap.Findings[j]
		if a.Status != b.Status {
			return Worse(a.Status, b.Status)
		}
		return a.ID < b.ID
	})
	for _, s := range c.latest {
		snap.Series = append(snap.Series, s)
	}
	sort.Slice(snap.Series, func(i, j int) bool { return snap.Series[i].Name < snap.Series[j].Name })
	return snap
}

// Latest returns the newest value of a series.
func (c *Collector) Latest(name string) (float64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.latest[name]
	return s.Value, ok
}

func safeSource(ctx context.Context, name string, fn Source) (out []Sample) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Messquelle abgestürzt", "quelle", name, "fehler", r)
			out = nil
		}
	}()
	return fn(ctx)
}

func safeCheck(ctx context.Context, name string, fn Check) (out []Finding) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Prüfung abgestürzt", "pruefung", name, "fehler", r)
			out = nil
		}
	}()
	return fn(ctx)
}

// validSeries keeps names safe for URLs and the database: lower-case
// letters, digits and . _ : / - , at most 120 bytes.
func validSeries(s string) bool {
	if s == "" || len(s) > 120 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == ':', r == '/', r == '-':
		default:
			return false
		}
	}
	return true
}

// ValidSeriesPattern checks a requested series name or prefix ("net:*").
func ValidSeriesPattern(s string) bool {
	if p, ok := cutStar(s); ok {
		return validSeries(p)
	}
	return validSeries(s)
}

func cutStar(s string) (string, bool) {
	if len(s) > 0 && s[len(s)-1] == '*' {
		return s[:len(s)-1], true
	}
	return s, false
}
