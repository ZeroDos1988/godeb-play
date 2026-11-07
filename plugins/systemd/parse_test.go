package systemd

import "testing"

func TestParseUnits(t *testing.T) {
	services := ParseUnits(sampleUnits + "broken not-a-unit\nfoo.service not-found inactive dead gone\n")
	if len(services) != 3 {
		t.Fatalf("services = %#v", services)
	}
	if services[2].Unit != "nginx.service" || services[2].Active != "inactive" {
		t.Fatalf("nginx = %#v", services[2])
	}
	if services[0].Description == "" {
		t.Fatal("missing description")
	}
}

func TestValidUnit(t *testing.T) {
	if !validUnit("cron.service") || !validUnit("user@1000.service") {
		t.Fatal("expected safe units")
	}
	if validUnit("godeb-play.service") || validUnit("godeb-play-agent.service") || validUnit("cron") || validUnit("../evil.service") || validUnit("-bad.service") {
		t.Fatal("expected rejection")
	}
}
