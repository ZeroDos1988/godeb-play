package agent

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRouted(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/plugins/ufw/status":    true,
		"/api/plugins/../auth/login": false,
		"/api/plugins":               false,
		"/api/plugin-manager":        true,
		"/api/plugin-manager/x/off":  true,
		"/api/plugin-managerx":       false,
		"/api/setup/finish":          true,
		"/api/setup/client":          true,
		"/api/setup/admin":           false,
		"/api/setup/status":          false,
		"/api/auth/login":            false,
		"/api/system":                false,
		"/":                          false,
	} {
		if got := Routed(p); got != want {
			t.Errorf("Routed(%q) = %v, want %v", p, got, want)
		}
	}
}

func startAgent(t *testing.T, peers Peers) (string, chan http.Header) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := Listen(sock, peers, "godeb-test-user-does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan http.Header, 4)
	srv := &http.Server{Handler: Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "body": string(body)})
	}))}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock, seen
}

func TestListenSocketMode(t *testing.T) {
	sock, _ := startAgent(t, AllowedPeers("nobody-here"))
	st, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o660 || st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("mode %v", st.Mode())
	}
	// A regular file at the socket path is never deleted.
	file := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(file, AllowedPeers(""), ""); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
}

func TestProxyForwardsIdentityAndDropsSpoofedHeaders(t *testing.T) {
	sock, seen := startAgent(t, AllowedPeers("nobody-here"))
	var verdictSession string
	proxy := NewProxy(sock, func(r *http.Request) Identity {
		return Identity{User: "alice", Session: "token-1"}
	}, func(session string, h http.Header) { verdictSession = session })
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/ufw/rules", strings.NewReader(`{"a":1}`))
	req.AddCookie(&http.Cookie{Name: "godeb_session", Value: "secret-jwt"})
	req.Header.Set(UserHeader, "root")
	req.Header.Set(SessionHeader, "forged")
	req.Header.Set("X-GoDeb-TOTP", "123456")
	req.Header.Set("X-GoDeb-Password", "secret-password")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["path"] != "/api/plugins/ufw/rules" || resp["body"] != `{"a":1}` {
		t.Fatalf("resp %v", resp)
	}
	h := <-seen
	if h.Get(UserHeader) != "alice" || h.Get(SessionHeader) != SessionID("token-1") {
		t.Fatalf("identity headers %v", h)
	}
	if h.Get("X-GoDeb-TOTP") != "123456" {
		t.Fatal("TOTP header must pass through for the agent's own check")
	}
	if h.Get("X-GoDeb-Password") != "" {
		t.Fatal("password header must not reach the agent")
	}
	if h.Get("Cookie") != "" {
		t.Fatal("session cookie was forwarded to the agent")
	}
	if verdictSession != "token-1" {
		t.Fatalf("verdict session %q", verdictSession)
	}
	if len(h.Values(UserHeader)) != 1 {
		t.Fatalf("spoofed user header survived: %v", h.Values(UserHeader))
	}

	// Without a session the identity headers are absent, not forged.
	proxy = NewProxy(sock, func(*http.Request) Identity { return Identity{} }, nil)
	req = httptest.NewRequest(http.MethodGet, "/api/plugins/wireguard/android", nil)
	req.Header.Set(UserHeader, "root")
	proxy.ServeHTTP(httptest.NewRecorder(), req)
	if h := <-seen; h.Get(UserHeader) != "" || h.Get(SessionHeader) != "" {
		t.Fatalf("headers %v", h)
	}
}

func TestGuardRefusesOtherPaths(t *testing.T) {
	sock, _ := startAgent(t, AllowedPeers("nobody-here"))
	proxy := NewProxy(sock, func(*http.Request) Identity { return Identity{} }, nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestPeerCheckRejectsUnknownUID(t *testing.T) {
	// Only uid 0 allowed: the test user (not root) is turned away.
	if os.Getuid() == 0 {
		t.Skip("runs as root")
	}
	sock, _ := startAgent(t, Peers{uids: map[uint32]bool{0: true}})
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /api/plugins/x HTTP/1.1\r\nHost: a\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("rejected peer got an answer: %q", buf[:n])
	}
}

func TestProxyAgentDown(t *testing.T) {
	proxy := NewProxy(filepath.Join(t.TempDir(), "missing.sock"), func(*http.Request) Identity { return Identity{} }, nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/apt/updates", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
}
