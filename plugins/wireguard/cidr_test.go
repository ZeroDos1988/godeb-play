package wireguard

import (
	"net/netip"
	"slices"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p.Masked()
}

func TestSubtractPrefixesEmptyExclude(t *testing.T) {
	in := []netip.Prefix{mustPrefix(t, "0.0.0.0/0"), mustPrefix(t, "::/0")}
	got := SubtractPrefixes(in, nil)
	if len(got) != 2 || got[0].String() != "0.0.0.0/0" || got[1].String() != "::/0" {
		t.Fatalf("got %v", got)
	}
}

func TestSubtractPrefixesHomeLAN(t *testing.T) {
	in := []netip.Prefix{mustPrefix(t, "0.0.0.0/0")}
	ex := []netip.Prefix{mustPrefix(t, "172.16.1.0/24")}
	got := SubtractPrefixes(in, ex)
	if len(got) == 0 {
		t.Fatal("expected remaining prefixes")
	}
	for _, p := range got {
		if p.Overlaps(mustPrefix(t, "172.16.1.0/24")) {
			t.Fatalf("result still overlaps exclude: %s", p)
		}
		if !mustPrefix(t, "0.0.0.0/0").Overlaps(p) {
			t.Fatalf("result outside original: %s", p)
		}
	}
	// Spot-check that public and other private space remain covered.
	for _, sample := range []string{"8.8.8.8", "10.0.0.1", "172.16.0.1", "172.16.2.1", "192.168.1.1"} {
		addr := netip.MustParseAddr(sample)
		covered := false
		for _, p := range got {
			if p.Contains(addr) {
				covered = true
				break
			}
		}
		if !covered {
			t.Fatalf("%s not covered after subtract", sample)
		}
	}
	excluded := netip.MustParseAddr("172.16.1.50")
	for _, p := range got {
		if p.Contains(excluded) {
			t.Fatalf("excluded address still covered by %s", p)
		}
	}
}

func TestSubtractPrefixesDifferentFamilyIgnored(t *testing.T) {
	in := []netip.Prefix{mustPrefix(t, "0.0.0.0/0")}
	ex := []netip.Prefix{mustPrefix(t, "fd00::/8")}
	got := SubtractPrefixes(in, ex)
	if len(got) != 1 || got[0].String() != "0.0.0.0/0" {
		t.Fatalf("got %v", got)
	}
}

func TestApplyExcludedIPs(t *testing.T) {
	allowed, excluded, err := ApplyExcludedIPs("0.0.0.0/0, ::/0", "172.16.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(excluded) != 1 || excluded[0] != "172.16.1.0/24" {
		t.Fatalf("excluded=%v", excluded)
	}
	if slices.Contains(allowed, "0.0.0.0/0") {
		t.Fatalf("wildcard should be expanded, got %v", allowed)
	}
	if !slices.Contains(allowed, "::/0") {
		t.Fatalf("IPv6 wildcard should remain, got %v", allowed)
	}
}

func TestApplyExcludedIPsInvalid(t *testing.T) {
	if _, _, err := ApplyExcludedIPs("not-a-net", ""); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := ApplyExcludedIPs("0.0.0.0/0", "bad"); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := ApplyExcludedIPs("10.0.0.0/24", "10.0.0.0/24"); err == nil {
		t.Fatal("expected empty-result error")
	}
}
