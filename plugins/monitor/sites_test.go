package monitor

import (
	"net/http"
	"testing"

	"godebplay/backend/metrics"
)

func TestBuildSiteStatus(t *testing.T) {
	snap := metrics.Snapshot{Time: 100, Status: metrics.StatusWarning,
		Findings: []metrics.Finding{
			{ID: "disk:/", Status: metrics.StatusWarning, Title: "Platte wird voll", Detail: "/ zu 90 %"},
			{ID: "updates", Status: metrics.StatusInfo, Title: "3 Updates"},
		},
		Series: []metrics.SeriesInfo{
			{Name: "cpu", Value: 12}, {Name: "disk:/", Value: 90}, {Name: "disk:/srv", Value: 40},
			{Name: "game:enshrouded:up", Value: 1}, {Name: "game:enshrouded:players", Value: 3}, {Name: "game:enshrouded:slots", Value: 16},
			{Name: "net:eth0:rx", Value: 1e6},
		}}
	st := BuildSiteStatus(snap, "heim-vm", 3600)
	if len(st.Findings) != 1 || st.Findings[0].Detail != "" && st.Findings[0].Detail != "/ zu 90 %" {
		t.Fatalf("findings = %+v", st.Findings)
	}
	if st.Values["cpu"] != 12 || st.Values["disk"] != 90 || len(st.Values) != 2 {
		t.Fatalf("values = %v", st.Values)
	}
	if len(st.Games) != 1 || !st.Games[0].Up || st.Games[0].Players != 3 || st.Games[0].Slots != 16 {
		t.Fatalf("games = %+v", st.Games)
	}
}

func TestSiteAnswersOnlyTheHub(t *testing.T) {
	startTest(t)
	// No wg0.conf here: this host is no peer, so nobody gets an answer.
	if code := get(t, "/api/plugins/monitor/site", nil); code != http.StatusNotFound {
		t.Fatalf("status = %d", code)
	}
}
