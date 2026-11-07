package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"godebplay/backend/core"
)

const (
	// maxCodeAttempts bounds wrong TOTP/backup codes per pending login and per
	// session. The row is deleted on the last failure, so brute forcing needs
	// the password (pending) or a fresh 2FA login (session) again.
	maxCodeAttempts = 5
	// touchInterval throttles last_seen writes to one per minute and session.
	touchInterval = time.Minute
)

var errTooManyAttempts = errors.New("Zu viele Fehlversuche")

// session is one server-side login. ID is the SHA-256 of the token ID inside
// the signed cookie, so a database leak does not yield usable cookies.
type session struct {
	ID            string
	Username      string
	Stage         string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastSeen      time.Time
	ElevatedUntil time.Time
	Failures      int
	IP            string
	UserAgent     string
}

// SessionInfo is what the UI lists under "Sitzungen".
type SessionInfo struct {
	ID            string    `json:"id"`
	Current       bool      `json:"current"`
	CreatedAt     time.Time `json:"created_at"`
	LastSeen      time.Time `json:"last_seen"`
	ExpiresAt     time.Time `json:"expires_at"`
	ElevatedUntil time.Time `json:"elevated_until,omitempty"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent"`
}

func newTokenID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func sessionKey(tokenID string) string {
	sum := sha256.Sum256([]byte(tokenID))
	return hex.EncodeToString(sum[:])
}

// startSession stores a new pending or full session and returns its signed cookie value.
func startSession(r *http.Request, username, stage, ver string, ttl time.Duration) (string, error) {
	conn, err := ready()
	if err != nil {
		return "", err
	}
	tokenID, err := newTokenID()
	if err != nil {
		return "", err
	}
	t := now().UTC()
	if _, err := conn.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, t.Unix()); err != nil {
		return "", err
	}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	_, err = conn.Exec(
		`INSERT INTO sessions (id, username, stage, created_at, expires_at, last_seen, ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionKey(tokenID), username, stage, t.Unix(), t.Add(ttl).Unix(), t.Unix(), core.ClientIP(r), ua,
	)
	if err != nil {
		return "", err
	}
	return issue(username, stage, ver, tokenID, ttl)
}

// loadSession returns the live row for a token ID or errSession.
func loadSession(tokenID, stage string) (session, error) {
	var s session
	conn, err := ready()
	if err != nil {
		return s, err
	}
	var created, expires, seen, elevated int64
	err = conn.QueryRow(
		`SELECT id, username, stage, created_at, expires_at, last_seen, elevated_until, failures, ip, user_agent
		 FROM sessions WHERE id = ?`,
		sessionKey(tokenID),
	).Scan(&s.ID, &s.Username, &s.Stage, &created, &expires, &seen, &elevated, &s.Failures, &s.IP, &s.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return session{}, errSession
	}
	if err != nil {
		return session{}, err
	}
	s.CreatedAt = time.Unix(created, 0).UTC()
	s.ExpiresAt = time.Unix(expires, 0).UTC()
	s.LastSeen = time.Unix(seen, 0).UTC()
	if elevated > 0 {
		s.ElevatedUntil = time.Unix(elevated, 0).UTC()
	}
	if s.Stage != stage || !now().Before(s.ExpiresAt) {
		return session{}, errSession
	}
	return s, nil
}

func touchSession(s session) {
	t := now()
	if t.Sub(s.LastSeen) < touchInterval {
		return
	}
	if conn, err := ready(); err == nil {
		_, _ = conn.Exec(`UPDATE sessions SET last_seen = ? WHERE id = ?`, t.Unix(), s.ID)
	}
}

func deleteSession(id string) error {
	conn, err := ready()
	if err != nil {
		return err
	}
	_, err = conn.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// recordFailure counts a wrong code and returns the attempts left. At zero the
// session is gone and errTooManyAttempts is returned.
func recordFailure(id string) (int, error) {
	conn, err := ready()
	if err != nil {
		return 0, err
	}
	mu.Lock()
	defer mu.Unlock()
	var failures int
	if err := conn.QueryRow(`UPDATE sessions SET failures = failures + 1 WHERE id = ? RETURNING failures`, id).Scan(&failures); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errTooManyAttempts
		}
		return 0, err
	}
	if failures >= maxCodeAttempts {
		if _, err := conn.Exec(`DELETE FROM sessions WHERE id = ?`, id); err != nil {
			return 0, err
		}
		return 0, errTooManyAttempts
	}
	return maxCodeAttempts - failures, nil
}

// elevate resets the failure counter and opens the step-up window.
func elevate(id string, until time.Time) error {
	conn, err := ready()
	if err != nil {
		return err
	}
	_, err = conn.Exec(`UPDATE sessions SET failures = 0, elevated_until = ? WHERE id = ?`, until.Unix(), id)
	return err
}

// ListSessions returns the user's active full sessions, newest first.
func ListSessions(username, currentID string) ([]SessionInfo, error) {
	conn, err := ready()
	if err != nil {
		return nil, err
	}
	rows, err := conn.Query(
		`SELECT id, created_at, last_seen, expires_at, elevated_until, ip, user_agent FROM sessions
		 WHERE username = ? AND stage = ? AND expires_at > ? ORDER BY created_at DESC`,
		username, stageFull, now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []SessionInfo{}
	for rows.Next() {
		var info SessionInfo
		var created, seen, expires, elevated int64
		if err := rows.Scan(&info.ID, &created, &seen, &expires, &elevated, &info.IP, &info.UserAgent); err != nil {
			return nil, err
		}
		info.Current = info.ID == currentID
		info.CreatedAt = time.Unix(created, 0).UTC()
		info.LastSeen = time.Unix(seen, 0).UTC()
		info.ExpiresAt = time.Unix(expires, 0).UTC()
		if elevated > now().Unix() {
			info.ElevatedUntil = time.Unix(elevated, 0).UTC()
		}
		list = append(list, info)
	}
	return list, rows.Err()
}

// RevokeSession ends one session of username. It reports false for unknown IDs.
func RevokeSession(username, id string) (bool, error) {
	conn, err := ready()
	if err != nil {
		return false, err
	}
	res, err := conn.Exec(`DELETE FROM sessions WHERE id = ? AND username = ?`, id, username)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RevokeSessions ends every session of username except keepID (may be empty)
// and returns how many were ended. `godeb-play sessions revoke` passes no keepID.
func RevokeSessions(username, keepID string) (int, error) {
	if !ValidUsername(username) {
		return 0, ErrInvalidUsername
	}
	conn, err := ready()
	if err != nil {
		return 0, err
	}
	res, err := conn.Exec(`DELETE FROM sessions WHERE username = ? AND id <> ?`, username, keepID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
