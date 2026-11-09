package steam

import (
	"os"
	"strings"
	"testing"

	"godebplay/plugins/wireguard"
)

func TestValheimSettingsRoundTrip(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	g, ok := lookup("valheim")
	if !ok {
		t.Fatal("valheim not registered")
	}
	raw, err := g.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := g.ValidateConfig(raw)
	if err != nil {
		t.Fatalf("default config invalid: %v\n%s", err, raw)
	}
	if err := writeSettings(g, cfg); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(g.settingsPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`VALHEIM_NAME="GoDeb Play Valheim"`, `VALHEIM_WORLD="Dedicated"`, `VALHEIM_PUBLIC="0"`, `VALHEIM_PORT="2456"`} {
		if !strings.Contains(string(env), want) {
			t.Errorf("settings miss %s:\n%s", want, env)
		}
	}
	if info, _ := os.Stat(g.settingsPath()); info.Mode().Perm() != 0o600 {
		t.Errorf("settings mode %v", info.Mode())
	}
	unit := renderUnit(g, protonPinned)
	for _, want := range []string{"EnvironmentFile=" + g.settingsPath(), "-password ${VALHEIM_PASSWORD}", "Environment=SteamAppId=892970", "/server/linux64"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit misses %q", want)
		}
	}
	if got := valheimPorts(cfg); len(got) != 2 || got[0] != 2456 || got[1] != 2457 {
		t.Errorf("ports %v", got)
	}
}

func TestValheimRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"short password": `{"name":"Wikinger","world":"W","password":"abc"}`,
		"name in pw":     `{"name":"Wikinger","world":"W","password":"xxWikingerxx"}`,
		"quote":          `{"name":"a\"b c","world":"W","password":"secret1"}`,
		"newline":        `{"name":"abc\ndef","world":"W","password":"secret1"}`,
		"dollar":         `{"name":"abc","world":"W","password":"$HOME1"}`,
		"world path":     `{"name":"abc","world":"../x","password":"secret1"}`,
		"low port":       `{"name":"abc","world":"W","password":"secret1","port":80}`,
	} {
		if _, err := validateValheim([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSatisfactoryPortsAndFirewall(t *testing.T) {
	g, ok := lookup("satisfactory")
	if !ok {
		t.Fatal("satisfactory not registered")
	}
	if tcp := g.TCPPorts(nil); len(tcp) != 2 || tcp[1] != 8888 {
		t.Fatalf("tcp %v", tcp)
	}
	args := strings.Join(ufwArgs(g, wireguard.RoleInfo{Role: wireguard.RolePeer}, "", 8888, "tcp"), " ")
	if args != "allow in on wg0 to any port 8888 proto tcp comment GoDeb Play Satisfactory" {
		t.Fatal(args)
	}
	if strings.Contains(renderUnit(g, protonPinned), "EnvironmentFile") {
		t.Fatal("satisfactory has no settings file")
	}
}

func TestRenderSettingsRejectsInjection(t *testing.T) {
	for _, v := range []string{"a\"b", "a\nb", "$x", "a\\b", "%n", "a;b"} {
		if _, err := renderSettings(map[string]string{"X_NAME": v}); err == nil {
			t.Errorf("value %q accepted", v)
		}
	}
	if _, err := renderSettings(map[string]string{"lower": "x"}); err == nil {
		t.Error("bad name accepted")
	}
}

// FuzzValheimSettings: whatever passes validation must render to an
// environment file with exactly one KEY="value" line per setting.
func FuzzValheimSettings(f *testing.F) {
	f.Add(`{"name":"GoDeb Play Valheim","world":"Dedicated","password":"geheim123","public":true,"port":2456}`)
	f.Add(`{"name":"x\"y","world":"a b","password":"$(id)"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		cfg, err := validateValheim([]byte(raw))
		if err != nil {
			return
		}
		env, err := valheimSettings(cfg)
		if err != nil {
			return
		}
		body, err := renderSettings(env)
		if err != nil {
			t.Fatalf("validated config does not render: %v (%q)", err, raw)
		}
		lines := strings.Split(strings.TrimSpace(body), "\n")
		if len(lines) != len(env)+1 {
			t.Fatalf("lines %d for %d settings:\n%s", len(lines), len(env), body)
		}
		for _, l := range lines[1:] {
			if strings.Count(l, `"`) != 2 || !strings.HasSuffix(l, `"`) {
				t.Fatalf("bad line %q", l)
			}
		}
	})
}
