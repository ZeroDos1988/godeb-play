package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	SessionCookie = "godeb_session"
	PendingCookie = "godeb_pending"

	sessionTTL = 12 * time.Hour
	pendingTTL = 5 * time.Minute

	stageFull    = "full"
	stagePending = "pending"

	pendingPath = "/api/auth/2fa"
)

var errSession = errors.New("Sitzung ungültig")

type claims struct {
	Stage   string `json:"stg"`
	Version string `json:"ver"`
	jwt.RegisteredClaims
}

var (
	keyMu    sync.Mutex
	keyCache = map[string][]byte{}
)

// signingKey loads or creates the HMAC key next to the auth files.
func signingKey() ([]byte, error) {
	path := filepath.Join(Dir(), "jwt.key")
	keyMu.Lock()
	defer keyMu.Unlock()
	if key, ok := keyCache[path]; ok {
		return key, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		raw = []byte(hex.EncodeToString(buf))
		if err := writePrivate(path, raw); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(string(raw))
	if err != nil || len(key) < 32 {
		return nil, errors.New("jwt.key ist beschädigt")
	}
	keyCache[path] = key
	return key, nil
}

// version binds a token to the current password hash and 2FA secret, so a
// password change or `godeb-play 2fa reset` invalidates existing sessions.
func version(passwordHash, secretFP string) string {
	sum := sha256.Sum256([]byte(passwordHash + "\x00" + secretFP))
	return hex.EncodeToString(sum[:8])
}

func issue(username, stage, ver, tokenID string, ttl time.Duration) (string, error) {
	key, err := signingKey()
	if err != nil {
		return "", err
	}
	t := now()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		Stage:   stage,
		Version: ver,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   username,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(t),
			ExpiresAt: jwt.NewNumericDate(t.Add(ttl)),
		},
	})
	return tok.SignedString(key)
}

func parse(raw, stage string) (claims, error) {
	var c claims
	key, err := signingKey()
	if err != nil {
		return c, err
	}
	_, err = jwt.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(now),
	)
	if err != nil || c.Stage != stage || c.ID == "" || !ValidUsername(c.Subject) {
		return claims{}, errSession
	}
	return c, nil
}

// pendingSession returns the login that passed the password step.
func pendingSession(r *http.Request) (session, error) {
	cookie, err := r.Cookie(PendingCookie)
	if err != nil {
		return session{}, errSession
	}
	c, err := parse(cookie.Value, stagePending)
	if err != nil {
		return session{}, err
	}
	hash, err := passwordHash(c.Subject)
	if err != nil || version(hash, "") != c.Version {
		return session{}, errSession
	}
	s, err := loadSession(c.ID, stagePending)
	if err != nil || s.Username != c.Subject {
		return session{}, errSession
	}
	return s, nil
}

// currentSession returns the fully authenticated session behind the cookie.
// The token must be signed, bound to the current password and 2FA secret, and
// still present in the sessions table (logout and revocation delete it).
func currentSession(r *http.Request) (session, error) {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		return session{}, errSession
	}
	c, err := parse(cookie.Value, stageFull)
	if err != nil {
		return session{}, err
	}
	hash, err := passwordHash(c.Subject)
	if err != nil {
		return session{}, errSession
	}
	_, fp, err := secondFactor.Status(c.Subject)
	if err != nil || fp == "" || version(hash, fp) != c.Version {
		return session{}, errSession
	}
	s, err := loadSession(c.ID, stageFull)
	if err != nil || s.Username != c.Subject {
		return session{}, errSession
	}
	return s, nil
}

// SessionIdentity returns user and session id of a fully authenticated
// session cookie. The agent proxy forwards both (the id only hashed).
func SessionIdentity(r *http.Request) (username, id string, err error) {
	s, err := currentSession(r)
	if err != nil {
		return "", "", err
	}
	return s.Username, s.ID, nil
}

// SessionUser returns the user of a fully authenticated session cookie.
func SessionUser(r *http.Request) (string, error) {
	s, err := currentSession(r)
	if err != nil {
		return "", err
	}
	return s.Username, nil
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value, path string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secureCookies(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func clearCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureCookies(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func secureCookies(r *http.Request) bool {
	return r.TLS != nil || os.Getenv("GODEB_COOKIE_SECURE") == "1"
}
