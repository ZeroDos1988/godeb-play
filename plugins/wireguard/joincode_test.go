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

func TestCompleteJoinCode(t *testing.T) {
	code := JoinCode(siteClientConf())
	if !CompleteJoinCode(code+"\n") || CompleteJoinCode(code[:len(code)/2]) || CompleteJoinCode(siteClientConf()) {
		t.Fatal("CompleteJoinCode wrong")
	}
}
