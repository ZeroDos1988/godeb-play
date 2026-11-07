// Package authlog writes failed login attempts in the line format that the
// fail2ban filter /etc/fail2ban/filter.d/godeb.conf matches.
package authlog

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultPath is the file watched by the godeb fail2ban jail.
const DefaultPath = "/var/log/godeb-play/auth.log"

// The date layout must stay one that fail2ban's default date detector finds.
const timeLayout = "2006-01-02 15:04:05"

// Logger appends one line per failed attempt.
type Logger struct {
	path string
	mu   sync.Mutex
	now  func() time.Time
}

// New returns a Logger for GODEB_AUTH_LOG, or DefaultPath when it is unset.
func New() *Logger {
	path := os.Getenv("GODEB_AUTH_LOG")
	if path == "" {
		path = DefaultPath
	}
	return &Logger{path: path, now: time.Now}
}

// Path returns the log file location.
func (l *Logger) Path() string {
	return l.path
}

// FailedLogin records `[TIMESTAMP] FAILED_LOGIN ip=<IP> user=<USERNAME>` in the
// file and in the journal. Lines without a parseable IP are not written to the
// file so fail2ban never tries to ban a hostname.
func (l *Logger) FailedLogin(ip, user string) {
	user = sanitizeUser(user)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		slog.Warn("Anmeldung fehlgeschlagen", "benutzer", user, "ip", "?")
		return
	}
	slog.Warn("Anmeldung fehlgeschlagen", "benutzer", user, "ip", parsed.String())

	line := fmt.Sprintf("[%s] FAILED_LOGIN ip=%s user=%s\n", l.now().Format(timeLayout), parsed, user)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.append(line); err != nil {
		slog.Error("auth.log nicht beschreibbar", "pfad", l.path, "fehler", err)
	}
}

func (l *Logger) append(line string) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// sanitizeUser keeps attacker-supplied names from injecting a second
// "ip=" token or a line break into the fail2ban log.
func sanitizeUser(user string) string {
	var b strings.Builder
	for _, r := range user {
		if b.Len() >= 32 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
