package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image/png"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"godebplay/backend/db"
	"godebplay/backend/security"
)

const (
	issuer          = "GoDeb"
	totpPeriod      = 30
	backupCodeCount = 8
	backupCodeLen   = 10
	// 32 symbols divide 256 evenly, so byte % 32 is unbiased.
	backupAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

var totpOpts = totp.ValidateOpts{
	Period:    totpPeriod,
	Digits:    otp.DigitsSix,
	Algorithm: otp.AlgorithmSHA1,
}

type twoFactorFile struct {
	Username    string    `json:"username"`
	Secret      string    `json:"secret"`
	Confirmed   bool      `json:"confirmed"`
	BackupCodes []string  `json:"backup_codes"`
	LastStep    int64     `json:"last_step"`
	CreatedAt   time.Time `json:"created_at"`
}

// Enrollment is shown to the user once. Only bcrypt hashes of the backup codes are stored.
type Enrollment struct {
	Secret      string   `json:"secret"`
	OTPAuthURL  string   `json:"otpauth_url"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

func twoFactorPath(username string) string {
	return filepath.Join(Dir(), "2fa_"+username+".json")
}

func load2FA(username string) (twoFactorFile, error) {
	if !ValidUsername(username) {
		return twoFactorFile{}, ErrInvalidUsername
	}
	conn, err := twoFactorConn()
	if err != nil {
		return twoFactorFile{}, err
	}
	return loadLocal2FA(conn, twoFactorKeyPath(), username)
}

// twoFactorKeyPath is the key sealing TOTP secrets and backup codes: next
// to the agent database, root-only (/etc/godeb-play/master.key), unless
// GODEB_AGENT_MASTER_KEY says otherwise. The web process never reads it.
func twoFactorKeyPath() string {
	return db.AgentKeyPath()
}

// loadLocal2FA reads the enrollment from conn (the agent database, or the
// web database with its own key when scrubbing an old copy).
func loadLocal2FA(conn *sql.DB, keyPath, username string) (twoFactorFile, error) {
	var rec twoFactorFile
	var confirmed int
	var codes, created string
	err := conn.QueryRow(
		`SELECT totp_secret, totp_confirmed, backup_codes, last_step, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&rec.Secret, &confirmed, &codes, &rec.LastStep, &created)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && rec.Secret == "") {
		return twoFactorFile{}, ErrNotEnrolled
	}
	if err != nil {
		return rec, err
	}
	rec.Secret, err = security.OpenWith(keyPath, rec.Secret)
	if err != nil {
		return rec, err
	}
	if rec.Secret == "" {
		return twoFactorFile{}, ErrNotEnrolled
	}
	codes, err = security.OpenWith(keyPath, codes)
	if err != nil {
		return rec, err
	}
	rec.Username = username
	rec.Confirmed = confirmed == 1
	if codes != "" && codes != "[]" {
		if err := json.Unmarshal([]byte(codes), &rec.BackupCodes); err != nil {
			return rec, err
		}
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return rec, nil
}

func write2FA(conn *sql.DB, rec twoFactorFile) error {
	raw, err := json.Marshal(rec.BackupCodes)
	if err != nil {
		return err
	}
	secret, err := security.SealWith(twoFactorKeyPath(), rec.Secret)
	if err != nil {
		return err
	}
	codes, err := security.SealWith(twoFactorKeyPath(), string(raw))
	if err != nil {
		return err
	}
	confirmed := 0
	if rec.Confirmed {
		confirmed = 1
	}
	var exists int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, rec.Username).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		_, err = conn.Exec(
			`INSERT INTO users (username, password_hash, created_at, totp_secret, totp_confirmed, backup_codes, last_step)
			 VALUES (?, '', ?, ?, ?, ?, ?)`,
			rec.Username, rec.CreatedAt.UTC().Format(time.RFC3339), secret, confirmed, codes, rec.LastStep,
		)
		return err
	}
	_, err = conn.Exec(
		`UPDATE users SET totp_secret = ?, totp_confirmed = ?, backup_codes = ?, last_step = ? WHERE username = ?`,
		secret, confirmed, codes, rec.LastStep, rec.Username,
	)
	return err
}

// importLegacy2FA copies 2fa_<user>.json into the users table once.
func importLegacy2FA(conn *sql.DB) error {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		username, ok := strings.CutPrefix(entry.Name(), "2fa_")
		if !ok {
			continue
		}
		username, ok = strings.CutSuffix(username, ".json")
		if !ok || !ValidUsername(username) {
			continue
		}
		var rec twoFactorFile
		if err := readJSON(twoFactorPath(username), &rec); err != nil || rec.Secret == "" {
			continue
		}
		var current string
		scanErr := conn.QueryRow(`SELECT totp_secret FROM users WHERE username = ?`, username).Scan(&current)
		if scanErr == nil && current != "" {
			continue
		}
		rec.Username = username
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = now().UTC()
		}
		if err := write2FA(conn, rec); err != nil {
			return err
		}
	}
	return nil
}

// Generate2FASecret creates a pending enrollment with a new secret, QR code and
// backup codes. A confirmed enrollment is never replaced; use Reset2FA first.
func Generate2FASecret(username string) (Enrollment, error) {
	if !ValidUsername(username) {
		return Enrollment{}, ErrInvalidUsername
	}
	mu.Lock()
	defer mu.Unlock()

	existing, err := load2FA(username)
	switch {
	case err == nil && existing.Confirmed:
		return Enrollment{}, ErrAlreadyEnrolled
	case err != nil && !errors.Is(err, ErrNotEnrolled):
		return Enrollment{}, err
	}

	account := username
	if host, err := os.Hostname(); err == nil && host != "" {
		account += "@" + host
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      totpPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return Enrollment{}, err
	}
	img, err := key.Image(256, 256)
	if err != nil {
		return Enrollment{}, err
	}
	var qr bytes.Buffer
	if err := png.Encode(&qr, img); err != nil {
		return Enrollment{}, err
	}
	codes, hashes, err := newBackupCodes()
	if err != nil {
		return Enrollment{}, err
	}

	rec := twoFactorFile{
		Username:    username,
		Secret:      key.Secret(),
		BackupCodes: hashes,
		CreatedAt:   now().UTC(),
	}
	conn, err := twoFactorConn()
	if err != nil {
		return Enrollment{}, err
	}
	if err := write2FA(conn, rec); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{
		Secret:      key.Secret(),
		OTPAuthURL:  key.URL(),
		QRCode:      "data:image/png;base64," + base64.StdEncoding.EncodeToString(qr.Bytes()),
		BackupCodes: codes,
	}, nil
}

// Confirm2FA activates a pending enrollment once the first TOTP code matches.
func Confirm2FA(username, code string) (bool, error) {
	mu.Lock()
	defer mu.Unlock()

	rec, err := load2FA(username)
	if err != nil {
		return false, err
	}
	if rec.Confirmed {
		return false, ErrAlreadyEnrolled
	}
	if !checkTOTP(&rec, code) {
		return false, nil
	}
	rec.Confirmed = true
	conn, err := twoFactorConn()
	if err != nil {
		return false, err
	}
	if err := write2FA(conn, rec); err != nil {
		return false, err
	}
	return true, dropGrant(conn, username)
}

// ValidateTOTP accepts a current 6-digit TOTP code or an unused backup code.
// Each TOTP time step and each backup code is accepted only once.
func ValidateTOTP(username, code string) (bool, error) {
	mu.Lock()
	defer mu.Unlock()

	rec, err := load2FA(username)
	if err != nil {
		return false, err
	}
	if !rec.Confirmed {
		return false, ErrNotEnrolled
	}
	if !checkTOTP(&rec, code) && !consumeBackupCode(&rec, code) {
		return false, nil
	}
	conn, err := twoFactorConn()
	if err != nil {
		return false, err
	}
	return true, write2FA(conn, rec)
}

// Enrolled reports whether username has a confirmed 2FA enrollment.
func Enrolled(username string) (bool, error) {
	rec, err := load2FA(username)
	if errors.Is(err, ErrNotEnrolled) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return rec.Confirmed, nil
}

// Reset2FA deletes the enrollment and lets the next login start a new one
// (root only: the CLI, never the web process).
func Reset2FA(username string) error {
	if !ValidUsername(username) {
		return ErrInvalidUsername
	}
	conn, err := twoFactorConn()
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	res, err := conn.Exec(
		`UPDATE users SET totp_secret = '', totp_confirmed = 0, backup_codes = '[]', last_step = 0
		 WHERE username = ? AND totp_secret <> ''`,
		username,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotEnrolled
	}
	return GrantEnrollment(username)
}

// secretFingerprint changes whenever the enrollment is reset or replaced.
func secretFingerprint(username string) (string, error) {
	rec, err := load2FA(username)
	if err != nil {
		return "", err
	}
	if !rec.Confirmed {
		return "", ErrNotEnrolled
	}
	return fingerprintOf(rec.Secret), nil
}

func fingerprintOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

func checkTOTP(rec *twoFactorFile, code string) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return false
	}
	current := now().Unix() / totpPeriod
	for _, offset := range []int64{-1, 0, 1} {
		step := current + offset
		if step <= rec.LastStep {
			continue
		}
		want, err := totp.GenerateCodeCustom(rec.Secret, time.Unix(step*totpPeriod, 0), totpOpts)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			rec.LastStep = step
			return true
		}
	}
	return false
}

func consumeBackupCode(rec *twoFactorFile, code string) bool {
	normalized := normalizeBackupCode(code)
	if len(normalized) != backupCodeLen {
		return false
	}
	for i, hash := range rec.BackupCodes {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(normalized)) == nil {
			rec.BackupCodes = append(rec.BackupCodes[:i:i], rec.BackupCodes[i+1:]...)
			return true
		}
	}
	return false
}

func normalizeBackupCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	return strings.NewReplacer("-", "", " ", "").Replace(code)
}

func newBackupCodes() (codes, hashes []string, err error) {
	for range backupCodeCount {
		raw := make([]byte, backupCodeLen)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		for i, b := range raw {
			raw[i] = backupAlphabet[int(b)%len(backupAlphabet)]
		}
		hash, err := bcrypt.GenerateFromPassword(raw, bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, string(raw[:5])+"-"+string(raw[5:]))
		hashes = append(hashes, string(hash))
	}
	return codes, hashes, nil
}
