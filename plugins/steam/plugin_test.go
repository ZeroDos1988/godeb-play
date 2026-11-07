package steam

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"godebplay/plugins/wireguard"
)

func enshrouded(t *testing.T) *Game {
	t.Helper()
	g, ok := lookup("enshrouded")
	if !ok {
		t.Fatal("enshrouded not registered")
	}
	return g
}

func TestDefaultConfigValidates(t *testing.T) {
	raw, err := enshroudedDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := validateEnshrouded(raw)
	if err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	if got := enshroudedPorts(cfg); len(got) != 2 || got[0] != 15636 || got[1] != 15637 {
		t.Fatalf("ports = %v", got)
	}
}

func TestValidateConfigRejects(t *testing.T) {
	cases := map[string]string{
		"not json":      `{`,
		"array":         `[]`,
		"trailing":      `{} {}`,
		"slots":         `{"slotCount": 17}`,
		"port":          `{"queryPort": 80}`,
		"fraction":      `{"queryPort": 15637.5}`,
		"ip":            `{"ip": "nope"}`,
		"absolute dir":  `{"saveDirectory": "/etc"}`,
		"escape dir":    `{"logDirectory": "../../etc"}`,
		"preset":        `{"gameSettingsPreset": "Cheat"}`,
		"group dup":     `{"userGroups": [{"name": "A"}, {"name": "A"}]}`,
		"group control": `{"userGroups": [{"name": "A", "password": "x\ny"}]}`,
		"voice":         `{"enableVoiceChat": "yes"}`,
	}
	for name, raw := range cases {
		if _, err := validateEnshrouded([]byte(raw)); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
}

func TestValidateConfigKeepsUnknownKeys(t *testing.T) {
	raw := `{"name": "Test", "gamePort": 15636, "queryPort": 15637, "gameSettings": {"playerHealthFactor": 1.5}, "futureKey": [1, 2]}`
	cfg, err := validateEnshrouded([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["futureKey"]; !ok {
		t.Fatal("unknown key dropped")
	}
	if got := enshroudedPorts(cfg); len(got) != 2 || got[0] != 15636 {
		t.Fatalf("ports = %v", got)
	}
}

func TestExtractTarGzRejectsTraversal(t *testing.T) {
	dest := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("x")
	_ = tw.WriteHeader(&tar.Header{Name: "ok/steamcmd.sh", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.WriteHeader(&tar.Header{Name: "../evil", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	tw.Close()
	gz.Close()
	r, rerr := os.OpenRoot(dest)
	if rerr != nil {
		t.Fatal(rerr)
	}
	defer r.Close()
	err := extractTarGzIn(&buf, r, ".", os.Getuid(), os.Getgid())
	if err == nil || !strings.Contains(err.Error(), "verlässt") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "ok", "steamcmd.sh")); err != nil {
		t.Fatalf("regular file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "evil")); err == nil {
		t.Fatal("file escaped destination")
	}
}

func TestUnitIsSandboxed(t *testing.T) {
	g := enshrouded(t)
	unit := renderUnit(g)
	for _, want := range []string{
		"User=steam-enshrouded", "ProtectSystem=strict", "ReadWritePaths=/var/lib/godeb-play-games/enshrouded",
		"NoNewPrivileges=yes", "CapabilityBoundingSet=", "KillSignal=SIGINT",
		"ExecStart=/usr/bin/wine /var/lib/godeb-play-games/enshrouded/server/enshrouded_server.exe",
		"Environment=WINEPREFIX=/var/lib/godeb-play-games/enshrouded/wine",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit misses %q", want)
		}
	}
}

func TestConfigRoundTrip(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	g := enshrouded(t)
	mux := http.NewServeMux()
	Mount(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/steam/games/enshrouded/config", nil))
	var got configResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Exists {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}

	content := `{"name": "Mein Server", "slotCount": 4, "custom": true}`
	body, _ := json.Marshal(putConfigRequest{Content: content})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/plugins/steam/games/enshrouded/config", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("put = %d %s", rec.Code, rec.Body)
	}
	saved, err := os.ReadFile(g.configPath())
	if err != nil || string(saved) != content+"\n" {
		t.Fatalf("saved = %q, %v", saved, err)
	}

	body, _ = json.Marshal(putConfigRequest{Content: `{"slotCount": 99}`})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/plugins/steam/games/enshrouded/config", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid put = %d", rec.Code)
	}
}

func TestAdoptServerFilesReportsBuild(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	g := enshrouded(t)
	j := &jobHandle{r: &jobRunner{job: &Job{Log: []string{}}}}
	if err := os.MkdirAll(g.baseDir(), 0o750); err != nil {
		t.Fatal(err)
	}
	r, err := g.openBase()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := adoptServerFiles(g, j, r, os.Getuid(), os.Getgid()); err != nil || len(j.r.job.Log) != 0 {
		t.Fatalf("empty dir: err=%v log=%v", err, j.r.job.Log)
	}
	manifest := filepath.Join(g.serverDir(), "steamapps", "appmanifest_"+g.AppID+".acf")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(g.executable(), []byte("MZ"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("\"AppState\"\n{\n\t\"buildid\"\t\t\"20311475\"\n}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := adoptServerFiles(g, j, r, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if len(j.r.job.Log) != 1 || !strings.Contains(j.r.job.Log[0], "Build 20311475") {
		t.Fatalf("log=%v", j.r.job.Log)
	}
}

func TestUfwArgsBehindHub(t *testing.T) {
	g := enshrouded(t)
	public := strings.Join(ufwArgs(g, wireguard.RoleInfo{}, "192.168.1.0/24", 15637), " ")
	if public != "allow from 192.168.1.0/24 to any port 15637 proto udp comment GoDeb Play Enshrouded" {
		t.Fatalf("standalone: %s", public)
	}
	peer := strings.Join(ufwArgs(g, wireguard.RoleInfo{Role: wireguard.RolePeer, Hub: "203.0.113.7:51820"}, "", 15637), " ")
	if peer != "allow in on wg0 to any port 15637 proto udp comment GoDeb Play Enshrouded" {
		t.Fatalf("behind hub: %s", peer)
	}
}

func TestSteamArgs(t *testing.T) {
	g := enshrouded(t)
	got := strings.Join(steamArgs(g), " ")
	want := "/var/lib/godeb-play-games/enshrouded/steamcmd/steamcmd.sh +@sSteamCmdForcePlatformType windows +force_install_dir /var/lib/godeb-play-games/enshrouded/server +login anonymous +app_update 2278520 validate +quit"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	linux := &Game{ID: "testlinux", AppID: "1", Platform: Linux, Executable: "srv", Ports: func(map[string]any) []int { return nil }}
	if strings.Contains(strings.Join(steamArgs(linux), " "), "ForcePlatformType") {
		t.Fatal("Linux servers must not force the Windows platform")
	}
	if strings.Contains(renderUnit(linux), "wine") {
		t.Fatal("Linux servers must not start under Wine")
	}
}

func TestRegisterRejectsBadGames(t *testing.T) {
	ports := func(map[string]any) []int { return nil }
	bad := map[string]*Game{
		"id":         {ID: "Bad-ID", AppID: "1", Platform: Linux, Executable: "srv", Ports: ports},
		"duplicate":  {ID: "enshrouded", AppID: "1", Platform: Linux, Executable: "srv", Ports: ports},
		"app id":     {ID: "x1", AppID: "12a", Platform: Linux, Executable: "srv", Ports: ports},
		"platform":   {ID: "x2", AppID: "1", Platform: "mac", Executable: "srv", Ports: ports},
		"escape":     {ID: "x3", AppID: "1", Platform: Linux, Executable: "../../bin/sh", Ports: ports},
		"absolute":   {ID: "x4", AppID: "1", Platform: Linux, Executable: "/bin/sh", Ports: ports},
		"no ports":   {ID: "x5", AppID: "1", Platform: Linux, Executable: "srv"},
		"package":    {ID: "x6", AppID: "1", Platform: Linux, Executable: "srv", Ports: ports, Packages: []string{"wine; rm -rf /"}},
		"config fns": {ID: "x7", AppID: "1", Platform: Linux, Executable: "srv", Ports: ports, ConfigFile: "a.json"},
	}
	for name, g := range bad {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: registered", name)
				}
			}()
			register(g)
		}()
	}
	if _, ok := lookup("x1"); ok {
		t.Fatal("invalid game left in the registry")
	}
}

func TestUnknownGame(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux)
	for _, path := range []string{"/api/plugins/steam/games/nope/status", "/api/plugins/steam/games/..%2Fetc/status"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/steam/games", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"enshrouded"`) {
		t.Fatalf("games = %d %s", rec.Code, rec.Body)
	}
}

func TestJobBelongsToGame(t *testing.T) {
	var r jobRunner
	block := make(chan struct{})
	if err := r.start("enshrouded", "install", func(context.Context, *jobHandle) error { <-block; return nil }); err != nil {
		t.Fatal(err)
	}
	if r.snapshot("enshrouded") == nil || r.snapshot("other") != nil {
		t.Fatal("job must only show for its own game")
	}
	if err := r.start("other", "install", func(context.Context, *jobHandle) error { return nil }); err == nil {
		t.Fatal("second job started while one runs")
	}
	close(block)
}

// FuzzValidateEnshrouded: whatever the admin pastes, validation must not
// panic, and an accepted file must keep save and log paths inside the
// server directory and ports in range.
func FuzzValidateEnshrouded(f *testing.F) {
	def, _ := enshroudedDefaultConfig()
	f.Add(def)
	f.Add([]byte(`{"saveDirectory": "../../etc"}`))
	f.Add([]byte(`{"saveDirectory": "/etc", "queryPort": 70000}`))
	f.Add([]byte(`{"name": "x\u0000y"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		cfg, err := validateEnshrouded(raw)
		if err != nil {
			return
		}
		if dir := enshroudedSaveDir(cfg); !safeRelative(dir) {
			t.Fatalf("save dir %q accepted", dir)
		}
		for _, p := range enshroudedPorts(cfg) {
			if p < 1023 || p > 65535 {
				t.Fatalf("port %d accepted", p)
			}
		}
	})
}

func TestJobRunStreamsLines(t *testing.T) {
	j := &jobHandle{r: &jobRunner{job: &Job{Log: []string{}}}}
	if err := j.run(context.Background(), 10*time.Second, nil, "printf", `10%%\r50%%\rfertig\n`); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(j.r.job.Log, "|")
	if !strings.Contains(got, "10%|50%|fertig") {
		t.Fatalf("log = %q", got)
	}
	if err := j.run(context.Background(), 10*time.Second, nil, "false"); err == nil {
		t.Fatal("failing command reported no error")
	}
}
