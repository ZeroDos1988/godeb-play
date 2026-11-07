package firstrun

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"strings"

	"godebplay/backend/state"
)

// EnsureToken returns the one-time setup token, creating it if needed. The
// daemon and `godeb-play setup-url` may race; O_EXCL makes the first one win.
func EnsureToken() (string, error) {
	if tok, err := readToken(); err == nil {
		return tok, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	err := state.CreateExclusive(tokenPath(), []byte(tok+"\n"), 0o600)
	if errors.Is(err, fs.ErrExist) {
		return readToken()
	}
	if err != nil {
		return "", err
	}
	return tok, nil
}

func readToken() (string, error) {
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fs.ErrNotExist
	}
	return tok, nil
}

// CheckToken compares in constant time.
func CheckToken(got string) bool {
	want, err := readToken()
	if err != nil || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(want)) == 1
}
