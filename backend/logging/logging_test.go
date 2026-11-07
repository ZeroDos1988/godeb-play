package logging

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJournalPrefixAndNoTime(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "agent", slog.LevelDebug, true)
	l.Error("kaputt", "x", 1)
	l.Debug("detail")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	if !strings.HasPrefix(lines[0], "<3>level=ERROR msg=kaputt komponente=agent x=1") {
		t.Fatalf("error line = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "<7>level=DEBUG") {
		t.Fatalf("debug line = %q", lines[1])
	}
	if strings.Contains(buf.String(), "time=") {
		t.Fatalf("journal lines carry no timestamp: %q", buf.String())
	}
}

func TestTerminalKeepsTime(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "web", slog.LevelInfo, false).Info("hallo")
	if !strings.HasPrefix(buf.String(), "time=") {
		t.Fatalf("line = %q", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, " WARN ": slog.LevelWarn, "error": slog.LevelError, "": slog.LevelInfo, "quatsch": slog.LevelInfo} {
		if got := ParseLevel(in); got != want {
			t.Fatalf("%q = %v", in, got)
		}
	}
}

func TestTruncateKeepsRunes(t *testing.T) {
	if got := Truncate("äöü", 3); got != "ä …" {
		t.Fatalf("got %q", got)
	}
	if got := Truncate(" kurz \n", 10); got != "kurz" {
		t.Fatalf("got %q", got)
	}
}

func captureDefault(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(New(&buf, "test", level, true))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestAuditLevels(t *testing.T) {
	buf := captureDefault(t, slog.LevelInfo)
	h := Audit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if User(r.Context()) != "admin" {
			t.Errorf("user not in context")
		}
		switch r.URL.Path {
		case "/ok":
			Annotate(r.Context(), slog.String("2fa", "bestätigt"))
			w.WriteHeader(http.StatusOK)
		case "/code":
			Expected(r.Context())
			w.WriteHeader(http.StatusForbidden)
		case "/deny":
			w.WriteHeader(http.StatusForbidden)
		case "/boom":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}), AuditOptions{
		User: func(*http.Request) string { return "admin" },
		IP:   func(*http.Request) string { return "10.8.0.5" },
	})
	for _, p := range []string{"/ok", "/code", "/deny", "/boom"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, p, nil))
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ok", nil))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{
		`<6>level=INFO msg=Aktion komponente=test methode=POST pfad=/ok status=200`,
		`<6>level=INFO msg="Aktion wartet auf Bestätigung"`,
		`<4>level=WARN msg="Aktion abgelehnt"`,
		`<3>level=ERROR msg="Aktion fehlgeschlagen"`,
	}
	if len(lines) != len(want) {
		t.Fatalf("GET must stay at debug; lines = %q", lines)
	}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w) {
			t.Fatalf("line %d = %q, want prefix %q", i, lines[i], w)
		}
	}
	if !strings.Contains(lines[0], "benutzer=admin ip=10.8.0.5 2fa=bestätigt") {
		t.Fatalf("fields missing: %q", lines[0])
	}
}

func TestAuditSkipAndQuiet(t *testing.T) {
	buf := captureDefault(t, slog.LevelInfo)
	h := Audit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), AuditOptions{
		Skip:  func(r *http.Request, _ int) bool { return r.URL.Path == "/skip" },
		Quiet: func(r *http.Request) bool { return r.URL.Path == "/quiet" },
	})
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/skip", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/quiet", nil))
	if buf.Len() != 0 {
		t.Fatalf("logged %q", buf.String())
	}
}

func TestStatusRecorderFlushes(t *testing.T) {
	rec := httptest.NewRecorder()
	h := Audit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
	}), AuditOptions{})
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !rec.Flushed {
		t.Fatal("not flushed")
	}
}

func TestAuditLogsErrorReason(t *testing.T) {
	buf := captureDefault(t, slog.LevelInfo)
	h := Audit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"nginx -t: unknown directive \"foo\""}`))
		case "/ok":
			_, _ = w.Write([]byte(`{"error":"not an error, status 200"}`))
		}
	}), AuditOptions{})
	for _, p := range []string{"/fail", "/ok"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, p, nil))
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	if !strings.Contains(lines[0], `fehler="nginx -t: unknown directive \"foo\""`) {
		t.Fatalf("reason missing: %q", lines[0])
	}
	if strings.Contains(lines[1], "fehler=") {
		t.Fatalf("success with error field logged as failure: %q", lines[1])
	}
}
