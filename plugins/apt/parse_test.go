package apt

import "testing"

func TestParseUpgradable(t *testing.T) {
	packages := ParseUpgradable(sampleUpgradable)
	if len(packages) != 2 {
		t.Fatalf("packages = %#v", packages)
	}
	if packages[0].Name != "bash" || packages[0].From != "5.2.37-2" || packages[0].Arch != "amd64" {
		t.Fatalf("first = %#v", packages[0])
	}
	if packages[1].Suite != "stable-security" || packages[1].Version != "3.5.7-1" {
		t.Fatalf("second = %#v", packages[1])
	}
	if len(ParseUpgradable("Listing...\n")) != 0 {
		t.Fatal("expected no packages")
	}
}
