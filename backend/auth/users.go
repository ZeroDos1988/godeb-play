package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"godebplay/backend/db"
	"godebplay/backend/security"

	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLen = 12
	// bcrypt ignores everything after 72 bytes.
	maxPasswordLen = 72
)

type usersFile struct {
	Users map[string]string `json:"users"`
}

var (
	dummyOnce sync.Once
	dummyHash []byte
)

func usersPath() string {
	return Dir() + "/users.json"
}

var (
	importMu   sync.Mutex
	importedDB = map[string]bool{}
)

// ready opens the metadata database and copies a legacy users.json in once.
func ready() (*sql.DB, error) {
	conn, err := db.Open()
	if err != nil {
		return nil, err
	}
	importMu.Lock()
	defer importMu.Unlock()
	path := db.Path()
	if importedDB[path] {
		return conn, nil
	}
	if err := importLegacyUsers(conn); err != nil {
		return nil, err
	}
	if err := importLegacy2FA(conn); err != nil {
		return nil, err
	}
	importedDB[path] = true
	return conn, nil
}

// importLegacyUsers copies bcrypt hashes from users.json without overwriting
// accounts that already live in SQLite.
func importLegacyUsers(conn *sql.DB) error {
	file, err := loadUsers()
	if err != nil || len(file.Users) == 0 {
		return err
	}
	for username, hash := range file.Users {
		if !ValidUsername(username) || hash == "" {
			continue
		}
		stored, err := security.Seal(hash)
		if err != nil {
			return err
		}
		_, err = conn.Exec(
			`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)
			 ON CONFLICT(username) DO NOTHING`,
			username, stored, time.Now().UTC().Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("Benutzer %s importieren: %w", username, err)
		}
	}
	return nil
}

func loadUsers() (usersFile, error) {
	file := usersFile{Users: map[string]string{}}
	err := readJSON(usersPath(), &file)
	if errors.Is(err, fs.ErrNotExist) {
		return file, nil
	}
	if file.Users == nil {
		file.Users = map[string]string{}
	}
	return file, err
}

// SetPassword creates the user or replaces its password hash.
func SetPassword(username, password string) error {
	if !ValidUsername(username) {
		return ErrInvalidUsername
	}
	if len(password) < minPasswordLen || len(password) > maxPasswordLen {
		return fmt.Errorf("Passwort muss %d bis %d Zeichen lang sein", minPasswordLen, maxPasswordLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	stored, err := security.Seal(string(hash))
	if err != nil {
		return err
	}
	conn, err := ready()
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	_, err = conn.Exec(
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash`,
		username, stored, now().UTC().Format(time.RFC3339),
	)
	return err
}

// CheckPassword returns the stored hash when the password matches. Unknown
// users still cost one bcrypt comparison so response times do not reveal them.
func CheckPassword(username, password string) (string, bool) {
	conn, err := ready()
	var hash string
	found := false
	if err == nil && ValidUsername(username) {
		scanErr := conn.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&hash)
		found = scanErr == nil
		if scanErr != nil && scanErr != sql.ErrNoRows {
			err = scanErr
		}
		if found {
			opened, openErr := security.Open(hash)
			if openErr != nil {
				found = false
			} else {
				hash = opened
			}
		}
	}
	if err != nil || !found || !ValidUsername(username) || len(password) > maxPasswordLen {
		dummyOnce.Do(func() {
			dummyHash, _ = bcrypt.GenerateFromPassword([]byte("godeb-dummy-password"), bcrypt.DefaultCost)
		})
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return "", false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", false
	}
	return hash, true
}

func passwordHash(username string) (string, error) {
	conn, err := ready()
	if err != nil {
		return "", err
	}
	var hash string
	err = conn.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", ErrInvalidUsername
	}
	if err != nil {
		return "", err
	}
	return security.Open(hash)
}

// UserExists reports whether username has an account.
func UserExists(username string) (bool, error) {
	if !ValidUsername(username) {
		return false, ErrInvalidUsername
	}
	_, err := passwordHash(username)
	if errors.Is(err, ErrInvalidUsername) {
		return false, nil
	}
	return err == nil, err
}

// HasUsers reports whether any local account exists. The setup wizard may
// only create the first administrator while it returns false.
func HasUsers() (bool, error) {
	conn, err := ready()
	if err != nil {
		return false, err
	}
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}
