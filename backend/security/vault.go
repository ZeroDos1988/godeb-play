// Package security seals database secrets with AES-256-GCM.
// The 32-byte master key lives in /etc/godeb-play/master.key (mode 0600).
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"godebplay/backend/state"
)

const (
	// DefaultKeyPath is the production master key in the web process's
	// state directory (it seals account secrets of the web database).
	DefaultKeyPath = "/var/lib/godeb-play/master.key"
	prefix         = "v1:"
	keySize        = 32
)

var (
	// ErrKeyLength is returned when the master key file is not 32 bytes.
	ErrKeyLength = errors.New("Master-Key muss 32 Byte lang sein")

	keyMu      sync.Mutex
	cachedKeys = map[string][]byte{}
)

// KeyPath returns GODEB_MASTER_KEY, the production path when that directory
// is writable, or a key file next to GODEB_DB for tests and unprivileged runs.
func KeyPath() string {
	if path := os.Getenv("GODEB_MASTER_KEY"); path != "" {
		return path
	}
	if dirWritable(filepath.Dir(DefaultKeyPath)) {
		return DefaultKeyPath
	}
	if dbPath := os.Getenv("GODEB_DB"); dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "master.key")
	}
	return filepath.Join(os.TempDir(), "godeb-master.key")
}

// IsSealed reports whether value was produced by Seal.
func IsSealed(value string) bool {
	return strings.HasPrefix(value, prefix)
}

// Seal encrypts plaintext. Empty values and values that are already sealed
// are returned unchanged so a second save cannot double-encrypt.
func Seal(plaintext string) (string, error) {
	return SealWith(KeyPath(), plaintext)
}

// SealWith is Seal with the key file at keyPath (created on first use).
func SealWith(keyPath, plaintext string) (string, error) {
	if plaintext == "" || IsSealed(plaintext) {
		return plaintext, nil
	}
	key, err := masterKey(keyPath)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	buf := make([]byte, 0, len(nonce)+len(sealed))
	buf = append(buf, nonce...)
	buf = append(buf, sealed...)
	return prefix + base64.StdEncoding.EncodeToString(buf), nil
}

// Open decrypts a sealed value. Legacy plaintext (no v1: prefix) is returned
// unchanged so existing rows stay readable until the next seal pass.
func Open(stored string) (string, error) {
	return OpenWith(KeyPath(), stored)
}

// OpenWith is Open with the key file at keyPath.
func OpenWith(keyPath, stored string) (string, error) {
	if stored == "" || !IsSealed(stored) {
		return stored, nil
	}
	key, err := masterKey(keyPath)
	if err != nil {
		return "", err
	}
	return OpenWithKey(key, stored)
}

// OpenWithKey is Open with a key already in memory.
func OpenWithKey(key []byte, stored string) (string, error) {
	if stored == "" || !IsSealed(stored) {
		return stored, nil
	}
	if len(key) != keySize {
		return "", ErrKeyLength
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil {
		return "", fmt.Errorf("Vault-Daten: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("Vault-Daten sind zu kurz")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("Vault-Entschlüsselung: %w", err)
	}
	return string(plain), nil
}

func masterKey(path string) ([]byte, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if key := cachedKeys[path]; len(key) == keySize {
		out := make([]byte, keySize)
		copy(out, key)
		return out, nil
	}
	key, err := loadOrCreate(path)
	if err != nil {
		return nil, err
	}
	cachedKeys[path] = key
	out := make([]byte, keySize)
	copy(out, key)
	return out, nil
}

func loadOrCreate(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("Master-Key-Verzeichnis: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != keySize {
			return nil, ErrKeyLength
		}
		key := make([]byte, keySize)
		copy(key, raw)
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := state.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func dirWritable(dir string) bool {
	file, err := os.CreateTemp(dir, ".godeb-keyprobe-*")
	if err != nil {
		return false
	}
	name := file.Name()
	file.Close()
	os.Remove(name)
	return true
}
