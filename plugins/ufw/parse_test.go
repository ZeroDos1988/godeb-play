package ufw

import "testing"

func TestParseStatus(t *testing.T) {
	status := ParseStatus(sampleStatus)
	if !status.Active || len(status.Rules) != 3 {
		t.Fatalf("status = %#v", status)
	}
	if status.Rules[0].To != "22/tcp" || status.Rules[0].Action != "ALLOW" || status.Rules[0].From != "Anywhere" {
		t.Fatalf("first = %#v", status.Rules[0])
	}
	if status.Rules[2].To != "22/tcp (v6)" {
		t.Fatalf("v6 = %#v", status.Rules[2])
	}

	inactive := ParseStatus("Status: inactive\n")
	if inactive.Active || len(inactive.Rules) != 0 {
		t.Fatalf("inactive = %#v", inactive)
	}
}

func TestValidRule(t *testing.T) {
	if !validRule("22/tcp") || !validRule("OpenSSH") || !validRule("51820/udp") {
		t.Fatal("expected safe rules")
	}
	if validRule("22/tcp;id") || validRule("-f") || validRule("../etc") || validRule("") {
		t.Fatal("expected rejection")
	}
}
