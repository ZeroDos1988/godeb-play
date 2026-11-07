package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"godebplay/backend/metrics"
	"godebplay/plugins/wireguard"
)

// A site (the home VM) watches its hub the other way round: a hub that is
// down entirely cannot send an alert itself. The site asks the hub's public
// health route over the tunnel every minute; after hubStale without an
// answer the light turns red and the alerts of the site go out.

const hubStale = 3 * time.Minute

type hubState struct {
	addr     netip.Addr
	lastOK   time.Time
	since    time.Time // first poll for this hub address
	lastErr  string
	checking bool // this host is a peer with a hub
}

var (
	hubMu sync.Mutex
	hub   hubState
)

func init() {
	extraServices = append(extraServices, runHub)
	metrics.RegisterCheck("hub", hubCheck)
}

// probeHub asks GoDeb on the hub for /api/health. Tests replace it.
var probeHub = func(ctx context.Context, addr netip.Addr) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(addr.String(), strconv.Itoa(sitePort))+"/api/health", nil)
	if err != nil {
		return err
	}
	resp, err := siteClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 4<<10)).Decode(&body); err != nil || !body.OK {
		return fmt.Errorf("Antwort ist kein GoDeb-Health-Check")
	}
	return nil
}

// hubAddr is the hub's tunnel address on a peer. Tests replace it.
var hubAddr = wireguard.HubTunnelAddr

func runHub(ctx context.Context, _ *metrics.Collector, _ *metrics.Store) {
	t := time.NewTicker(sitePoll)
	defer t.Stop()
	for {
		pollHub(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func pollHub(ctx context.Context, now time.Time) {
	addr, ok := hubAddr()
	if !ok {
		hubMu.Lock()
		hub = hubState{}
		hubMu.Unlock()
		return
	}
	err := probeHub(ctx, addr)
	hubMu.Lock()
	defer hubMu.Unlock()
	if !hub.checking || hub.addr != addr {
		hub = hubState{addr: addr, since: now, checking: true}
	}
	if err != nil {
		hub.lastErr = err.Error()
		return
	}
	hub.lastOK, hub.lastErr = now, ""
}

func hubCheck(context.Context) []metrics.Finding {
	hubMu.Lock()
	h := hub
	hubMu.Unlock()
	return hubFindings(h, time.Now())
}

func hubFindings(h hubState, now time.Time) []metrics.Finding {
	if !h.checking || h.lastErr == "" {
		return nil
	}
	last := h.lastOK
	if last.IsZero() {
		last = h.since
	}
	if now.Sub(last) < hubStale {
		return nil
	}
	detail := "Keine Antwort von " + h.addr.String() + ":" + strconv.Itoa(sitePort) + " über den Tunnel: " + h.lastErr
	if !h.lastOK.IsZero() {
		detail += " (zuletzt erreichbar " + h.lastOK.Format("02.01. 15:04") + ")"
	}
	return []metrics.Finding{{ID: "hub", Status: metrics.StatusCritical, Title: "Hub nicht erreichbar", Detail: detail}}
}
