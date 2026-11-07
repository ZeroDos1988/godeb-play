package systemd

import (
	"testing"
	"time"
)

func TestAutoRebootDue(t *testing.T) {
	on := RebootSettings{Auto: true, Time: "04:00"}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 7, h, m, 0, 0, time.Local) }
	up := 5 * time.Hour
	cases := []struct {
		name      string
		s         RebootSettings
		now       time.Time
		required  bool
		scheduled bool
		uptime    time.Duration
		want      bool
	}{
		{"window start", on, at(4, 0), true, false, up, true},
		{"inside window", on, at(4, 59), true, false, up, true},
		{"after window", on, at(5, 0), true, false, up, false},
		{"before window", on, at(3, 59), true, false, up, false},
		{"off", RebootSettings{Time: "04:00"}, at(4, 10), true, false, up, false},
		{"not required", on, at(4, 10), false, false, up, false},
		{"already scheduled", on, at(4, 10), true, true, up, false},
		{"just booted", on, at(4, 10), true, false, 30 * time.Minute, false},
		{"bad time", RebootSettings{Auto: true, Time: "4:00"}, at(4, 0), true, false, up, false},
		{"past midnight", RebootSettings{Auto: true, Time: "23:30"}, at(0, 15), true, false, up, true},
		{"past midnight, too late", RebootSettings{Auto: true, Time: "23:30"}, at(0, 30), true, false, up, false},
	}
	for _, c := range cases {
		if got := autoRebootDue(c.s, c.now, time.Time{}, c.required, c.scheduled, c.uptime); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	// Cancelled in this window: not again until the next night.
	if autoRebootDue(on, at(4, 5), at(4, 0), true, false, up) {
		t.Error("rescheduled after cancel in the same window")
	}
	if !autoRebootDue(on, at(4, 5), at(4, 0).AddDate(0, 0, -1), true, false, up) {
		t.Error("yesterday's run blocks today")
	}
}

func TestClockPattern(t *testing.T) {
	for _, ok := range []string{"00:00", "04:30", "23:59"} {
		if !clockPattern.MatchString(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"24:00", "4:00", "04:60", "04:00\n", "04:00 ; reboot", ""} {
		if clockPattern.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
