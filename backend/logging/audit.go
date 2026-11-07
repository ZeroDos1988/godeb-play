package logging

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuditOptions tell Audit who sent a request and which ones to leave out.
type AuditOptions struct {
	User func(*http.Request) string // logged-in user, "" if unknown
	IP   func(*http.Request) string // client address, "" if unknown
	// Skip leaves a finished request out of the log (e.g. another process
	// logs it already).
	Skip func(r *http.Request, status int) bool
	// Quiet logs a request like a read (debug unless it failed with 5xx),
	// for frequent internal calls.
	Quiet func(*http.Request) bool
}

// Audit logs every request that changes something ("Aktion", info; refused
// warn; server errors error) and reads at debug. Handlers can add fields
// with Annotate and mark a refusal as part of the normal flow with Expected.
func Audit(next http.Handler, opts AuditOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		user := ""
		if opts.User != nil {
			user = opts.User(r)
		}
		n := &notes{}
		ctx := context.WithValue(WithUser(r.Context(), user), notesKey{}, n)
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r.WithContext(ctx))

		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		if opts.Skip != nil && opts.Skip(r, status) {
			return
		}
		read := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions ||
			(opts.Quiet != nil && opts.Quiet(r))
		level, msg := slog.LevelInfo, "Aktion"
		switch {
		case status >= 500:
			level, msg = slog.LevelError, "Aktion fehlgeschlagen"
		case status >= 400 && n.isExpected():
			level, msg = slog.LevelInfo, "Aktion wartet auf Bestätigung"
		case status >= 400:
			level, msg = slog.LevelWarn, "Aktion abgelehnt"
		}
		if read {
			msg = "Anfrage"
			if status < 500 {
				level = slog.LevelDebug
			}
		}
		if !slog.Default().Enabled(ctx, level) {
			return
		}
		attrs := []slog.Attr{
			slog.String("methode", r.Method),
			slog.String("pfad", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("dauer", time.Since(start).Round(time.Millisecond)),
		}
		if user != "" {
			attrs = append(attrs, slog.String("benutzer", user))
		}
		if opts.IP != nil {
			if ip := opts.IP(r); ip != "" {
				attrs = append(attrs, slog.String("ip", ip))
			}
		}
		if reason := rec.errorText(); reason != "" {
			attrs = append(attrs, slog.String("fehler", reason))
		}
		attrs = append(attrs, n.attrs()...)
		slog.LogAttrs(ctx, level, msg, attrs...)
	})
}

type notesKey struct{}

type notes struct {
	mu       sync.Mutex
	list     []slog.Attr
	expected bool
}

func (n *notes) attrs() []slog.Attr {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]slog.Attr(nil), n.list...)
}

func (n *notes) isExpected() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.expected
}

// Annotate adds fields to the audit line of the request behind ctx. Outside
// Audit it does nothing.
func Annotate(ctx context.Context, attrs ...slog.Attr) {
	if n, ok := ctx.Value(notesKey{}).(*notes); ok {
		n.mu.Lock()
		n.list = append(n.list, attrs...)
		n.mu.Unlock()
	}
}

// Expected marks a 4xx answer as a normal step, such as asking for a 2FA
// code, so it is logged at info instead of warning.
func Expected(ctx context.Context) {
	if n, ok := ctx.Value(notesKey{}).(*notes); ok {
		n.mu.Lock()
		n.expected = true
		n.mu.Unlock()
	}
}

// statusRecorder remembers the status code; Unwrap keeps Flush and
// http.ResponseController working for streamed answers.
type statusRecorder struct {
	http.ResponseWriter
	status int
	// body keeps the start of an error answer (status >= 400) so the
	// audit line can say why a request failed, not only that it did.
	body []byte
}

// maxErrorBody bounds what is kept of an error answer.
const maxErrorBody = 2 << 10

// errorText is the "error" field of a JSON error answer, shortened.
func (s *statusRecorder) errorText() string {
	if s.status < 400 || len(s.body) == 0 {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(s.body, &payload) != nil {
		return ""
	}
	return Truncate(strings.TrimSpace(payload.Error), 300)
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if s.status >= 400 && len(s.body) < maxErrorBody {
		s.body = append(s.body, b[:min(len(b), maxErrorBody-len(s.body))]...)
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}
