package monitor

import (
	"testing"
	"time"

	"godebplay/backend/metrics"
)

func TestProfileAndJudge(t *testing.T) {
	now := time.Date(2026, 10, 23, 20, 30, 0, 0, time.Local) // Friday evening
	var pts []metrics.Point
	// Three past Fridays at 20:00 with ~200 KB/s, other hours quiet.
	for w := 1; w <= 3; w++ {
		at := time.Date(2026, 10, 23-7*w, 20, 0, 0, 0, time.Local)
		pts = append(pts, metrics.Point{float64(at.Unix()), 200e3 + float64(w), 0})
		quiet := at.Add(-10 * time.Hour)
		pts = append(pts, metrics.Point{float64(quiet.Unix()), 1e3, 0})
	}
	p := BuildProfile(pts, now)
	exp, ok := p.Expected(now)
	if !ok || exp != 200e3+2 {
		t.Fatalf("expected = %v %v", exp, ok)
	}
	if _, ok := p.Expected(now.Add(time.Hour)); ok {
		t.Fatal("no history for 21:00 must give no baseline")
	}
	// Friday evening game traffic is normal, a tenfold jump is not.
	if _, unusual := Judge("B/s", 250e3, exp); unusual {
		t.Fatal("normal evening traffic flagged")
	}
	if st, unusual := Judge("B/s", 900e3, exp); !unusual || st != metrics.StatusInfo {
		t.Fatalf("4.5x = %v %v", st, unusual)
	}
	if st, _ := Judge("B/s", 5e6, exp); st != metrics.StatusWarning {
		t.Fatalf("25x = %v", st)
	}
	if _, unusual := Judge("B/s", 50e3, 1e3); unusual {
		t.Fatal("small absolute change must not alarm")
	}
	if st, _ := Judge("%", 95, 20); st != metrics.StatusWarning {
		t.Fatalf("cpu = %v", st)
	}
}

func TestProfileDailyFallback(t *testing.T) {
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.Local)
	var pts []metrics.Point
	for d := 1; d <= 3; d++ {
		at := now.Add(-time.Duration(d) * 24 * time.Hour)
		pts = append(pts, metrics.Point{float64(at.Unix()), 10, 0})
	}
	if v, ok := BuildProfile(pts, now).Expected(now); !ok || v != 10 {
		t.Fatalf("daily = %v %v", v, ok)
	}
}
