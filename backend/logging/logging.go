// Package logging sets up structured logs for both GoDeb processes. Under
// systemd every line goes to the journal with a priority prefix, so
// `journalctl -u godeb -u godeb-play-agent -p warning` shows only problems.
// GODEB_LOG_LEVEL (debug, info, warn, error) picks the threshold.
package logging

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Setup installs the default slog logger for component ("web", "agent",
// "cli") on stderr. The standard log package is routed through it at info.
func Setup(component string) {
	slog.SetDefault(New(os.Stderr, component, ParseLevel(os.Getenv("GODEB_LOG_LEVEL")), os.Getenv("JOURNAL_STREAM") != ""))
	log.SetFlags(0)
}

// New builds a logger. journal adds the sd-daemon priority prefix and drops
// the timestamp, which the journal records itself.
func New(w io.Writer, component string, level slog.Level, journal bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if journal {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
		pw := &prefixWriter{w: w}
		h := &journalHandler{mu: &sync.Mutex{}, pw: pw, inner: slog.NewTextHandler(pw, opts)}
		return slog.New(h).With("komponente", component)
	}
	return slog.New(slog.NewTextHandler(w, opts)).With("komponente", component)
}

// ParseLevel maps GODEB_LOG_LEVEL to a slog level; unknown values are info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// Priority is the syslog priority journald files a level under.
func Priority(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return 3
	case l >= slog.LevelWarn:
		return 4
	case l >= slog.LevelInfo:
		return 6
	}
	return 7
}

// journalHandler writes "<prio>" in front of each record. The text handler
// emits one Write per record, so the prefix is set under the same lock.
type journalHandler struct {
	mu    *sync.Mutex
	pw    *prefixWriter
	inner slog.Handler
}

func (h *journalHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *journalHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pw.prio = Priority(r.Level)
	return h.inner.Handle(ctx, r)
}

func (h *journalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &journalHandler{mu: h.mu, pw: h.pw, inner: h.inner.WithAttrs(attrs)}
}

func (h *journalHandler) WithGroup(name string) slog.Handler {
	return &journalHandler{mu: h.mu, pw: h.pw, inner: h.inner.WithGroup(name)}
}

type prefixWriter struct {
	w    io.Writer
	prio int
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	buf := make([]byte, 0, len(b)+3)
	buf = append(buf, '<', byte('0'+p.prio), '>')
	buf = append(buf, b...)
	if _, err := p.w.Write(buf); err != nil {
		return 0, err
	}
	return len(b), nil
}

type actorKey struct{}

// WithUser attaches the acting GoDeb user to ctx, so commands run for a
// request are logged with it.
func WithUser(ctx context.Context, user string) context.Context {
	if user == "" {
		return ctx
	}
	return context.WithValue(ctx, actorKey{}, user)
}

// User returns the user set by WithUser, "" if none.
func User(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	u, _ := ctx.Value(actorKey{}).(string)
	return u
}

// Truncate shortens s to at most n bytes for a log line, on a rune boundary.
func Truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + " …"
}
