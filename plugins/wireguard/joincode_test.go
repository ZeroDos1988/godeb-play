package wireguard

import (
	"strings"
	"testing"
)

func TestJoinCodeRoundTrip(t *testing.T) {
	conf := siteClientConf()
	code := JoinCode(conf)
	if !strings.HasPrefix(code, JoinCodePrefix) || strings.ContainsAny(code, " \n=+/") {
		t.Fatalf("code is not one URL-safe line: %q", code)
	}
	// Wrapped by a terminal, with surrounding blanks and an upper-case prefix.
	body := strings.TrimPrefix(code, JoinCodePrefix)
	wrapped := "  GODEB-JOIN:" + body[:40] + "\n" + body[40:80] + " \r\n" + body[80:] + "\n"
	for _, in := range []string{code, wrapped} {
		got, err := decodeJoinInput(in)
		if err != nil {
			t.Fatal(err)
		}
		if got != conf {
			t.Fatalf("decoded config differs:\n%s", got)
		}
		if _, _, err := parseJoinConfig(got); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJoinCodePassesFilesThrough(t *testing.T) {
	conf := siteClientConf()
	if got, err := decodeJoinInput(conf); err != nil || got != conf {
		t.Fatalf("plain file changed: %v", err)
	}
}

func TestJoinCodeRejectsBroken(t *testing.T) {
	code := JoinCode(siteClientConf())
	for _, in := range []string{code[:len(code)-1] + "!", JoinCodePrefix + strings.Repeat("A", 40000)} {
		if _, err := decodeJoinInput(in); err == nil {
			t.Errorf("accepted %.40q", in)
		}
	}
	// A truncated code decodes, but the config must then fail validation.
	if got, err := decodeJoinInput(code[:len(code)/2]); err == nil {
		if _, _, err := parseJoinConfig(got); err == nil {
			t.Error("truncated code accepted")
		}
	}
}

func TestSiteAddressPrefersSecondHost(t *testing.T) {
	server := []string{"10.8.0.1/24"}
	if a, err := siteAddress(server, nil); err != nil || a.String() != "10.8.0.2" {
		t.Fatalf("got %v %v", a, err)
	}
	if _, err := siteAddress(server, []string{"10.8.0.2/32"}); err == nil {
		t.Fatal("taken address offered")
	}
}

func TestCompleteJoinCode(t *testing.T) {
	code := JoinCode(siteClientConf())
	if !CompleteJoinCode(code+"\n") || CompleteJoinCode(code[:len(code)/2]) || CompleteJoinCode(siteClientConf()) {
		t.Fatal("CompleteJoinCode wrong")
	}
}

func TestClientAddressKeepsSecondHostForSites(t *testing.T) {
	server := []string{"10.8.0.1/24"}
	pick := func(site, haveSite bool, used ...string) string {
		a, err := clientAddress(PeerRequest{Site: site}, server, used, haveSite)
		if err != nil {
			t.Fatal(err)
		}
		return a.String()
	}
	if got := pick(false, false); got != "10.8.0.3" {
		t.Errorf("first device got %s, want 10.8.0.3", got)
	}
	if got := pick(true, false, "10.8.0.3/32"); got != "10.8.0.2" {
		t.Errorf("first site got %s, want 10.8.0.2", got)
	}
	if got := pick(false, true, "10.8.0.2/32", "10.8.0.3/32"); got != "10.8.0.4" {
		t.Errorf("device after site got %s", got)
	}
	// An existing install where the phone already has .2: the site moves on.
	if got := pick(true, false, "10.8.0.2/32"); got != "10.8.0.3" {
		t.Errorf("site with .2 taken got %s", got)
	}
	// A /30 has only .1 and .2 as hosts: the device takes .2 rather than fail.
	if a, err := clientAddress(PeerRequest{}, []string{"10.9.0.1/30"}, nil, false); err != nil || a.String() != "10.9.0.2" {
		t.Errorf("small net: %v %v", a, err)
	}
	if a, err := clientAddress(PeerRequest{Address: "10.8.0.9"}, server, nil, false); err != nil || a.String() != "10.8.0.9" {
		t.Errorf("explicit: %v %v", a, err)
	}
}
