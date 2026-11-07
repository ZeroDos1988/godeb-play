package monitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"godebplay/backend/metrics"
)

// startTest wires a collector with a temporary database, as run() does.
func startTest(t *testing.T) *metrics.Collector {
	t.Helper()
	s, err := metrics.OpenStore(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	c := &metrics.Collector{Store: s}
	mu.Lock()
	collector, store = c, s
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		collector, store = nil, nil
		mu.Unlock()
		s.Close()
	})
	return c
}

func get(t *testing.T, path string, out any) int {
	t.Helper()
	mux := http.NewServeMux()
	Mount(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	return rec.Code
}

func TestUnavailableBeforeStart(t *testing.T) {
	if code := get(t, "/api/plugins/monitor/summary", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", code)
	}
}

func TestSummaryAndSeriesFromThisHost(t *testing.T) {
	c := startTest(t)
	ctx := context.Background()
	now := time.Now()
	c.Sample(ctx, now.Add(-10*time.Second))
	c.Sample(ctx, now)

	var sum summaryResponse
	if code := get(t, "/api/plugins/monitor/summary", &sum); code != http.StatusOK {
		t.Fatalf("summary = %d", code)
	}
	if sum.Host.Cores < 1 || sum.Interval != 10 {
		t.Fatalf("host = %+v", sum.Host)
	}
	if _, ok := c.Latest("mem"); !ok {
		t.Fatalf("no mem sample from /proc: %+v", sum.Series)
	}

	var r metrics.Range
	if code := get(t, "/api/plugins/monitor/series?names=mem,net:*&range=1h", &r); code != http.StatusOK {
		t.Fatalf("series = %d", code)
	}
	if len(r.Series["mem"]) == 0 {
		t.Fatalf("mem history missing: %v", r.Series)
	}
}

func TestSeriesRejectsBadInput(t *testing.T) {
	startTest(t)
	for _, p := range []string{
		"/api/plugins/monitor/series?names=mem&range=2y",
		"/api/plugins/monitor/series?names=&range=1h",
		"/api/plugins/monitor/series?names=*&range=1h",
		"/api/plugins/monitor/series?names=mem;drop&range=1h",
		"/api/plugins/monitor/events?range=forever",
	} {
		if code := get(t, p, nil); code != http.StatusBadRequest {
			t.Fatalf("%s = %d", p, code)
		}
	}
}

func TestEventsEndpoint(t *testing.T) {
	c := startTest(t)
	if err := c.Store.AddEvent(context.Background(), metrics.Event{Time: time.Now().Unix(), Source: "steam", Level: metrics.StatusInfo, Text: "Update gestartet"}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Events []metrics.Event `json:"events"`
	}
	if code := get(t, "/api/plugins/monitor/events?range=1h", &out); code != http.StatusOK || len(out.Events) != 1 {
		t.Fatalf("events = %d %+v", code, out)
	}
}
