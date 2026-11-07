package systemd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRejectsOwnUnit(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/systemd/action", strings.NewReader(`{"unit":"godeb-play.service","action":"stop"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestParseShowAndCatalog(t *testing.T) {
	units := ParseShow(sampleShow)
	if len(units) != 4 || units[0]["Id"] != "godeb-play.service" || units[3]["LoadState"] != "not-found" {
		t.Fatalf("units = %v", units)
	}
	if unixStamp(units[0]["ActiveEnterTimestamp"]) != 1761552000 || unixStamp("") != 0 || unixStamp("n/a") != 0 {
		t.Fatal("timestamps")
	}
	// Every catalog unit passes the unit pattern, and GoDeb's own are locked.
	for _, c := range catalog {
		if !unitPattern.MatchString(c.Unit) {
			t.Errorf("catalog unit %s does not match the pattern", c.Unit)
		}
	}
	if validUnit("godeb-play-agent.service") || !validUnit("ssh.service") {
		t.Fatal("lock list")
	}
}

func TestCPUPercent(t *testing.T) {
	s := cpuSampler{last: map[string]cpuSample{}}
	t0 := time.Unix(1000, 0)
	if p := s.percent("x", 1e9, t0); p != -1 {
		t.Fatalf("first sample = %v", p)
	}
	// 0.5 s CPU in 10 s wall time is 5 %.
	if p := s.percent("x", 1.5e9, t0.Add(10*time.Second)); p < 4.99 || p > 5.01 {
		t.Fatalf("percent = %v", p)
	}
	// A restart resets the counter: unknown, not negative.
	if p := s.percent("x", 1e6, t0.Add(20*time.Second)); p != -1 {
		t.Fatalf("after restart = %v", p)
	}
}

func TestRestartAllowed(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/systemd/action", strings.NewReader(`{"unit":"ssh.service","action":"reload-or-kill"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action accepted: %d", rec.Code)
	}
}
