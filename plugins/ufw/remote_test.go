package ufw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/doctor"
	"godebplay/backend/remoteaccess"
)

func setupRemote(t *testing.T) *[]string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GODEB_DB", filepath.Join(dir, "godeb.db"))
	t.Setenv("GODEB_AGENT_DB", filepath.Join(dir, "agent.db"))
	t.Setenv("GODEB_MASTER_KEY", filepath.Join(dir, "master.key"))
	t.Setenv("GODEB_STATE_DIR", filepath.Join(dir, "state"))
	oldIP, oldUFW := publicAddress, runRemoteUFW
	t.Cleanup(func() { publicAddress, runRemoteUFW = oldIP, oldUFW })
	publicAddress = func(context.Context) string { return "203.0.113.7" }
	var calls []string
	runRemoteUFW = func(_ context.Context, args ...string) core.CommandResult {
		calls = append(calls, strings.Join(args, " "))
		return core.CommandResult{}
	}
	return &calls
}

func TestRemoteOpenExpireClose(t *testing.T) {
	calls := setupRemote(t)
	ctx := context.Background()
	for _, d := range []time.Duration{time.Minute, 25 * time.Hour} {
		if _, err := OpenRemote(ctx, d); err == nil {
			t.Fatalf("%s accepted", d)
		}
	}
	r, err := OpenRemote(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Open || r.URL != "https://203.0.113.7:8443" || time.Until(r.Until) < 59*time.Minute {
		t.Fatalf("remote = %+v", r)
	}
	if got := (*calls)[len(*calls)-1]; got != "allow proto tcp to 203.0.113.7 port 8443 comment GoDeb Fernzugang" {
		t.Fatalf("ufw = %q", got)
	}
	if addr := remoteaccess.Load().Addr(time.Now()); addr != "203.0.113.7:8443" {
		t.Fatalf("web addr = %q", addr)
	}
	if remoteaccess.Load().Addr(time.Now().Add(2*time.Hour)) != "" {
		t.Fatal("web must stop serving after the deadline on its own")
	}

	// The overview warns with a close button.
	f := remoteFindings(ctx)
	if len(f) != 1 || f[0].Level != doctor.Warn || f[0].Fix == nil || f[0].Fix.Path != "/api/plugins/ufw/remote/close" {
		t.Fatalf("findings = %+v", f)
	}

	// Not yet expired: nothing happens.
	n := len(*calls)
	expireRemote(ctx, time.Now())
	if len(*calls) != n {
		t.Fatal("closed too early")
	}
	// Expired: rule removed, web told to close.
	expireRemote(ctx, time.Now().Add(2*time.Hour))
	if got := (*calls)[len(*calls)-1]; got != "delete allow proto tcp to 203.0.113.7 port 8443" {
		t.Fatalf("ufw = %q", got)
	}
	if remoteaccess.Load().Addr(time.Now()) != "" {
		t.Fatal("remote.json still open")
	}
	if s, _ := RemoteStatus(ctx); s.Open {
		t.Fatal("still open")
	}
	if f := remoteFindings(ctx); f != nil {
		t.Fatalf("findings after close = %+v", f)
	}
}

func TestRemoteRefusesWithoutUFWOrPublicIP(t *testing.T) {
	setupRemote(t)
	runRemoteUFW = func(context.Context, ...string) core.CommandResult {
		return core.CommandResult{Err: context.DeadlineExceeded}
	}
	if _, err := OpenRemote(context.Background(), time.Hour); err == nil {
		t.Fatal("opened without ufw")
	}
	publicAddress = func(context.Context) string { return "" }
	if _, err := OpenRemote(context.Background(), time.Hour); err == nil {
		t.Fatal("opened without address")
	}
}

func TestRemoteRoutes(t *testing.T) {
	calls := setupRemote(t)
	mux := http.NewServeMux()
	Mount(mux)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	if rec := do(http.MethodPost, remoteBase, `{"minutes":5}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("5 minutes: %d", rec.Code)
	}
	if rec := do(http.MethodPost, remoteBase, `{"minutes":30}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"open":true`) {
		t.Fatalf("open: %d %s", rec.Code, rec.Body)
	}
	if rec := do(http.MethodPost, remoteBase+"/close", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"open":false`) {
		t.Fatalf("close: %d %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix((*calls)[len(*calls)-1], "delete ") {
		t.Fatalf("calls = %v", *calls)
	}
}
