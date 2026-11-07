package monitor

import (
	"testing"
	"time"

	"godebplay/backend/metrics"
)

func TestValidateAlerts(t *testing.T) {
	ok := []AlertSettings{
		{Enabled: true, Email: " admin@example.org "},
		{Enabled: true, Ntfy: "https://ntfy.sh/godeb-abc123"},
		{Enabled: false},
	}
	for _, s := range ok {
		if _, err := ValidateAlerts(s); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
	}
	bad := []AlertSettings{
		{Enabled: true},
		{Email: "a@b.de, c@d.de"},
		{Ntfy: "http://ntfy.sh/x"},
		{Ntfy: "https://user:pw@ntfy.sh/x"},
		{Ntfy: "https://ntfy.sh/"},
		{Ntfy: "https://ntfy.sh/x?auth=1"},
	}
	for _, s := range bad {
		if _, err := ValidateAlerts(s); err == nil {
			t.Fatalf("%+v accepted", s)
		}
	}
	if s, _ := ValidateAlerts(AlertSettings{Level: "kaputt"}); s.Level != "warning" {
		t.Fatalf("level = %q", s.Level)
	}
}

func TestPlanAlerts(t *testing.T) {
	now := time.Now()
	sent := map[string]alertRecord{}
	s := AlertSettings{Enabled: true, Level: "warning", Resolved: true}
	disk := &metrics.Finding{ID: "disk:/", Status: metrics.StatusWarning, Title: "Platte wird voll"}
	info := &metrics.Finding{ID: "updates", Status: metrics.StatusInfo, Title: "3 Updates"}

	p, r := PlanAlerts([]alertChange{{nil, disk}, {nil, info}}, s, sent, now)
	if len(p) != 1 || len(r) != 0 {
		t.Fatalf("first = %v %v", p, r)
	}
	// Flapping back within the repeat window: no second mail.
	if p, _ := PlanAlerts([]alertChange{{nil, disk}}, s, sent, now.Add(time.Hour)); len(p) != 0 {
		t.Fatal("repeated too early")
	}
	// Worse: mail at once.
	crit := &metrics.Finding{ID: "disk:/", Status: metrics.StatusCritical, Title: "Platte fast voll"}
	if p, _ := PlanAlerts([]alertChange{{disk, crit}}, s, sent, now.Add(time.Hour)); len(p) != 1 {
		t.Fatal("escalation not sent")
	}
	// Resolved: one entry, and only for alarmed findings.
	_, r = PlanAlerts([]alertChange{{crit, nil}, {info, nil}}, s, sent, now.Add(2*time.Hour))
	if len(r) != 1 || r[0].ID != "disk:/" {
		t.Fatalf("resolved = %v", r)
	}

	critOnly := AlertSettings{Enabled: true, Level: "critical"}
	if p, _ := PlanAlerts([]alertChange{{nil, disk}}, critOnly, map[string]alertRecord{}, now); len(p) != 0 {
		t.Fatal("warning sent at level critical")
	}
	title, body, level := composeAlert([]metrics.Finding{*disk, *crit}, nil)
	if level != metrics.StatusCritical || body == "" || title == "" {
		t.Fatalf("compose = %q %q %v", title, body, level)
	}
}
