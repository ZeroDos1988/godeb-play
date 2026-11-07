package auth

import (
	"database/sql"
	"errors"
	"path/filepath"
	"time"

	"godebplay/backend/db"
	"godebplay/backend/security"
)

// SecondFactor is where TOTP secrets live and codes are checked. In-process
// that is the local store. With the root agent the web process uses a
// remote implementation and never sees a secret: the agent checks codes,
// keeps its own step-up windows and refuses new enrollments root did not
// allow (see EnrollAllowed).
type SecondFactor interface {
	// Status reports a confirmed enrollment and a fingerprint of the
	// secret that changes when the enrollment is reset or replaced.
	Status(username string) (enrolled bool, fingerprint string, err error)
	Generate(username string) (Enrollment, error)
	Confirm(username, code string) (bool, error)
	// Validate checks a code. session is the session id the code confirms
	// (empty at login); the agent opens its step-up window for it.
	Validate(username, code, session string) (bool, error)
}

type localSecondFactor struct{}

func (localSecondFactor) Status(username string) (bool, string, error) {
	enrolled, err := Enrolled(username)
	if err != nil || !enrolled {
		return false, "", err
	}
	fp, err := secretFingerprint(username)
	return err == nil, fp, err
}

func (localSecondFactor) Generate(username string) (Enrollment, error) {
	return Generate2FASecret(username)
}

func (localSecondFactor) Confirm(username, code string) (bool, error) {
	return Confirm2FA(username, code)
}

func (localSecondFactor) Validate(username, code, _ string) (bool, error) {
	return ValidateTOTP(username, code)
}

var secondFactor SecondFactor = localSecondFactor{}

// LocalSecondFactor is the store in this process (the agent's database).
func LocalSecondFactor() SecondFactor { return localSecondFactor{} }

// SetSecondFactor replaces the 2FA store (web process with root agent).
func SetSecondFactor(sf SecondFactor) { secondFactor = sf }

// stepUpElsewhere reports paths whose step-up check another process does
// (the root agent for the routes it serves). Codes for those paths must not
// be checked here as well: a TOTP step is accepted only once.
var stepUpElsewhere = func(string) bool { return false }

// DelegateStepUp hands the step-up check for matching paths to the agent.
func DelegateStepUp(fn func(path string) bool) { stepUpElsewhere = fn }

// twoFactorConn is the database holding TOTP secrets: the agent database,
// root-only. In development and tests it is the same file as the web one.
func twoFactorConn() (*sql.DB, error) {
	conn, err := db.AgentOpen()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS twofa_grants (
		username TEXT PRIMARY KEY,
		created_at TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		return nil, err
	}
	return conn, nil
}

// GrantEnrollment lets username set up 2FA through the web process once.
// Only root calls it (godeb-play user passwd, godeb-play 2fa reset).
func GrantEnrollment(username string) error {
	if !ValidUsername(username) {
		return ErrInvalidUsername
	}
	conn, err := twoFactorConn()
	if err != nil {
		return err
	}
	_, err = conn.Exec(`INSERT INTO twofa_grants (username, created_at) VALUES (?, ?)
		ON CONFLICT(username) DO NOTHING`, username, now().UTC().Format(time.RFC3339))
	return err
}

// EnrollAllowed decides whether the agent may start an enrollment asked for
// by the web process: for the very first account (nobody has 2FA yet), when
// root granted it, or to continue an enrollment that was allowed before.
// A compromised web process can therefore not enroll an account of its own
// and pass the agent's step-up check with it.
func EnrollAllowed(username string) (bool, error) {
	if !ValidUsername(username) {
		return false, ErrInvalidUsername
	}
	conn, err := twoFactorConn()
	if err != nil {
		return false, err
	}
	var confirmed, granted, pending int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM users WHERE totp_confirmed = 1 AND totp_secret <> ''`).Scan(&confirmed); err != nil {
		return false, err
	}
	if confirmed == 0 {
		return true, nil
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM twofa_grants WHERE username = ?`, username).Scan(&granted); err != nil {
		return false, err
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ? AND totp_secret <> '' AND totp_confirmed = 0`, username).Scan(&pending); err != nil {
		return false, err
	}
	return granted > 0 || pending > 0, nil
}

func dropGrant(conn *sql.DB, username string) error {
	_, err := conn.Exec(`DELETE FROM twofa_grants WHERE username = ?`, username)
	return err
}

// ScrubLocalSecrets removes TOTP secrets from the web database once the
// agent holds the same enrollment (the copy made when upgrading to the
// split). Enrollments the agent does not know are kept and reported.
func ScrubLocalSecrets(remote SecondFactor) ([]string, error) {
	if filepath.Clean(db.Path()) == filepath.Clean(db.AgentPath()) {
		// One file for both (development): these are the agent's secrets.
		return nil, nil
	}
	conn, err := ready()
	if err != nil {
		return nil, err
	}
	rows, err := conn.Query(`SELECT username FROM users WHERE totp_secret <> ''`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, name)
	}
	rows.Close()
	var kept []string
	scrubbed := 0
	for _, name := range names {
		rec, err := loadLocal2FA(conn, security.KeyPath(), name)
		if err != nil {
			kept = append(kept, name)
			continue
		}
		enrolled, fp, err := remote.Status(name)
		if err != nil || (rec.Confirmed && (!enrolled || fp != fingerprintOf(rec.Secret))) {
			kept = append(kept, name)
			continue
		}
		if _, err := conn.Exec(`UPDATE users SET totp_secret = '', totp_confirmed = 0, backup_codes = '[]', last_step = 0 WHERE username = ?`, name); err != nil {
			return kept, err
		}
		scrubbed++
	}
	if scrubbed > 0 {
		// Rewrite the file so the old secrets do not linger in free pages.
		if _, err := conn.Exec(`VACUUM`); err != nil {
			return kept, err
		}
	}
	if len(kept) > 0 {
		return kept, errors.New("2FA-Daten nicht beim Agenten")
	}
	return nil, nil
}
