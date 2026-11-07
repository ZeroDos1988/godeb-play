package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"godebplay/backend/state"
)

// DefaultDir holds users, 2FA secrets and the session signing key.
const DefaultDir = "/var/lib/godeb-play/auth"

var (
	ErrInvalidUsername = errors.New("ungültiger Benutzername")
	ErrNotEnrolled     = errors.New("2FA ist nicht eingerichtet")
	ErrAlreadyEnrolled = errors.New("2FA ist bereits eingerichtet")
	ErrEnrollForbidden = errors.New("2FA-Einrichtung für dieses Konto ist nicht freigegeben; als root: godeb-play 2fa reset <benutzer>")
)

var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// mu serialises read-modify-write cycles on the auth files inside one daemon.
var mu sync.Mutex

var now = time.Now

// ValidUsername accepts Debian-style login names. The name is used in file paths.
func ValidUsername(name string) bool {
	return usernamePattern.MatchString(name)
}

// Dir returns GODEB_AUTH_DIR or DefaultDir.
func Dir() string {
	if dir := os.Getenv("GODEB_AUTH_DIR"); dir != "" {
		return dir
	}
	return DefaultDir
}

func readJSON(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return state.WriteFile(path, data, 0o600)
}
