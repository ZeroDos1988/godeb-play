package metrics

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStoreRollupAndQuery(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base.Add(2 * time.Hour) }
	// Two hours of raw samples: cpu climbs from 0 to 719.
	for i := 0; i < 720; i++ {
		if err := s.Write(ctx, base.Unix()+int64(i*10), map[string]float64{"cpu": float64(i), "net:eth0:rx": 1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Rollup(ctx); err != nil {
		t.Fatal(err)
	}
	hourly, err := s.HourlyHistory(ctx, "cpu", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hourly) != 2 || hourly[0][1] != 179.5 || hourly[0][2] != 359 {
		t.Fatalf("hourly = %v", hourly)
	}
	// A second rollup must not duplicate or change anything.
	if err := s.Rollup(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.HourlyHistory(ctx, "cpu", 0); len(again) != 2 || again[1] != hourly[1] {
		t.Fatalf("second rollup = %v", again)
	}

	r, err := s.Query(ctx, []string{"cpu", "net:*"}, base.Unix(), base.Add(2*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if r.Step != 20 || len(r.Series["cpu"]) != 360 || len(r.Series["net:eth0:rx"]) != 360 {
		t.Fatalf("step %d, cpu %d, net %d", r.Step, len(r.Series["cpu"]), len(r.Series["net:eth0:rx"]))
	}
	if p := r.Series["cpu"][0]; p[1] != 0.5 || p[2] != 1 {
		t.Fatalf("first point = %v", p)
	}
}

func TestStoreUsesCoarseTierForOldWindows(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	old := now.Add(-10 * 24 * time.Hour).Unix()
	if _, err := s.db.Exec(`INSERT INTO points VALUES (1, 'cpu', ?, 42, 50), (2, 'cpu', ?, 7, 9)`, old, old); err != nil {
		t.Fatal(err)
	}
	r, err := s.Query(ctx, []string{"cpu"}, now.Add(-30*24*time.Hour).Unix(), now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Series["cpu"]) != 1 || r.Series["cpu"][0][1] != 42 {
		t.Fatalf("30 days from the 5-minute tier: %v", r.Series)
	}
	r, _ = s.Query(ctx, []string{"cpu"}, now.Add(-365*24*time.Hour).Unix(), now.Unix())
	if len(r.Series["cpu"]) != 1 || r.Series["cpu"][0][1] != 7 {
		t.Fatalf("a year from the hourly tier: %v", r.Series)
	}
}

func TestEvents(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i, text := range []string{"a", "b", "c"} {
		if err := s.AddEvent(ctx, Event{Time: int64(100 + i), Source: "test", Level: StatusInfo, Text: text}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Events(ctx, 0, 1000, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Text != "b" || got[1].Text != "c" {
		t.Fatalf("events = %+v", got)
	}
}

func TestCollectorRatesAndFindings(t *testing.T) {
	regMu.Lock()
	savedSources, savedChecks := sources, checks
	counter := 0.0
	sources = map[string]Source{"t": func(context.Context) []Sample {
		counter += 1000
		return []Sample{{Series: "net:x:rx", Value: counter, Counter: true}, {Series: "BAD NAME", Value: 1}}
	}}
	failing := true
	checks = map[string]Check{"t": func(context.Context) []Finding {
		if failing {
			return []Finding{{ID: "disk:/", Status: StatusWarning, Title: "voll"}}
		}
		return nil
	}}
	regMu.Unlock()
	defer func() {
		regMu.Lock()
		sources, checks = savedSources, savedChecks
		regMu.Unlock()
	}()

	s := openTestStore(t)
	var changes []string
	c := &Collector{Store: s, prev: map[string]counterValue{}, latest: map[string]SeriesInfo{}, findings: map[string]Finding{},
		FindingHook: func(old, new *Finding) {
			switch {
			case new != nil:
				changes = append(changes, "neu:"+new.ID)
			case old != nil:
				changes = append(changes, "weg:"+old.ID)
			}
		}}
	ctx := context.Background()
	t0 := time.Unix(1_000_000, 0)
	c.Sample(ctx, t0)
	if _, ok := c.Latest("net:x:rx"); ok {
		t.Fatal("first counter reading has no rate")
	}
	c.Sample(ctx, t0.Add(10*time.Second))
	if v, ok := c.Latest("net:x:rx"); !ok || v != 100 {
		t.Fatalf("rate = %v %v", v, ok)
	}
	if _, ok := c.Latest("BAD NAME"); ok {
		t.Fatal("invalid series stored")
	}
	c.RunChecks(ctx)
	if snap := c.Snapshot(); snap.Status != StatusWarning || len(snap.Findings) != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	c.RunChecks(ctx) // unchanged: no second report
	failing = false
	c.RunChecks(ctx)
	if len(changes) != 2 || changes[0] != "neu:disk:/" || changes[1] != "weg:disk:/" {
		t.Fatalf("changes = %v", changes)
	}
	if c.Snapshot().Status != StatusOK {
		t.Fatal("status must be ok again")
	}
}

func TestProcReaders(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3\n")
	write("net/dev", "Inter-|   Receive\n face |bytes packets\n    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n   wg0: 7 1 0 0 0 0 0 0 9 1 0 0 0 0 0 0\n")
	write("diskstats", "   8       0 sda 1 0 4 0 2 0 8 0 0 0 0\n   8       1 sda1 1 0 4 0 2 0 8 0 0 0 0\n 259 0 nvme0n1 1 0 2 0 1 0 2 0 0 0 0\n")
	saved := procRoot
	procRoot = dir
	defer func() { procRoot = saved }()

	cpu, ok := readCPUTimes()
	if !ok || cpu.total != 1000 || cpu.idle != 700 || cpu.iowait != 100 {
		t.Fatalf("cpu = %+v", cpu)
	}
	net := readNetDev()
	if len(net) != 2 || net["eth0"] != [2]uint64{1000, 2000} || net["wg0"] != [2]uint64{7, 9} {
		t.Fatalf("net = %v", net)
	}
	disks := readDiskstats()
	if len(disks) != 2 || disks["sda"] != [2]uint64{2048, 4096} {
		t.Fatalf("disks = %v", disks)
	}
}

func TestParseFailedUnits(t *testing.T) {
	got := ParseFailedUnits("godeb-steam-enshrouded.service loaded failed failed Enshrouded\n\n")
	if len(got) != 1 || got[0].ID != "unit:godeb-steam-enshrouded.service" || got[0].Status != StatusCritical {
		t.Fatalf("got = %+v", got)
	}
}

func TestSeriesNames(t *testing.T) {
	for _, ok := range []string{"cpu", "net:wg0:rx", "disk:/var/lib", "net:*"} {
		if !ValidSeriesPattern(ok) {
			t.Fatalf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "*", "CPU", "a b", "x;drop", string(make([]byte, 200))} {
		if ValidSeriesPattern(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
	if got := SeriesPart("Handy Anna/2"); got != "handy_anna/2" {
		t.Fatalf("SeriesPart = %q", got)
	}
}
