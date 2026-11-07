package monitor

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestHubWatch(t *testing.T) {
	addr := netip.MustParseAddr("10.8.0.1")
	oldAddr, oldProbe := hubAddr, probeHub
	t.Cleanup(func() { hubAddr, probeHub = oldAddr, oldProbe; hub = hubState{} })
	hubAddr = func() (netip.Addr, bool) { return addr, true }
	var fail error
	probeHub = func(context.Context, netip.Addr) error { return fail }

	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	pollHub(context.Background(), t0)
	if f := hubFindings(hub, t0.Add(10*time.Minute)); f != nil {
		t.Fatalf("reachable hub reported: %+v", f)
	}
	fail = errors.New("timeout")
	pollHub(context.Background(), t0.Add(time.Minute))
	if f := hubFindings(hub, t0.Add(2*time.Minute)); f != nil {
		t.Fatalf("short outage must not alert: %+v", f)
	}
	f := hubFindings(hub, t0.Add(4*time.Minute))
	if len(f) != 1 || f[0].ID != "hub" || f[0].Status != "critical" {
		t.Fatalf("outage not reported: %+v", f)
	}
	fail = nil
	pollHub(context.Background(), t0.Add(5*time.Minute))
	if f := hubFindings(hub, t0.Add(5*time.Minute)); f != nil {
		t.Fatalf("recovered hub still reported: %+v", f)
	}

	// Not a peer: nothing to watch.
	hubAddr = func() (netip.Addr, bool) { return netip.Addr{}, false }
	pollHub(context.Background(), t0)
	if hub.checking || hubFindings(hub, t0.Add(time.Hour)) != nil {
		t.Fatal("hub watched without a hub")
	}
}
