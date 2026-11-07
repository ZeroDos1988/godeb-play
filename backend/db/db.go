// Package db opens the embedded metadata databases. Runtime state of the
// host stays in OS files; the databases only store accounts, preferences and
// address assignments.
//
// There are two files with the same schema. The web database
// (/var/lib/godeb-play/godeb.db, web user) holds accounts, sessions, settings and
// OIDC. The agent database (/etc/godeb-play/godeb.db, root only) holds what the
// plugins remember: WireGuard addresses, mail domains, plugin state. So the
// unprivileged web process can never write data the root agent acts on.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"godebplay/backend/security"
	"godebplay/backend/state"
)

// DefaultPath is the web database, DefaultAgentPath the agent database.
const (
	DefaultPath      = "/var/lib/godeb-play/godeb.db"
	DefaultAgentPath = "/etc/godeb-play/godeb.db"
)

type handle struct {
	conn *sql.DB
	gorm *gorm.DB
}

var (
	openMu  sync.Mutex
	handles = map[string]*handle{}
)

// Path returns GODEB_DB or DefaultPath.
func Path() string {
	if path := os.Getenv("GODEB_DB"); path != "" {
		return path
	}
	return DefaultPath
}

// AgentPath returns GODEB_AGENT_DB. Without it a GODEB_DB of a development
// run or a test also holds the agent tables; otherwise DefaultAgentPath.
func AgentPath() string {
	if path := os.Getenv("GODEB_AGENT_DB"); path != "" {
		return path
	}
	if path := os.Getenv("GODEB_DB"); path != "" {
		return path
	}
	return DefaultAgentPath
}

// AgentKeyPath is the key that seals secrets in the agent database (2FA,
// plugin secrets): GODEB_AGENT_MASTER_KEY, otherwise master.key next to the
// agent database (/etc/godeb-play/master.key). The web process never reads it.
func AgentKeyPath() string {
	if p := os.Getenv("GODEB_AGENT_MASTER_KEY"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(AgentPath()), "master.key")
}

// Open returns the web database, creating the file and applying migrations.
func Open() (*sql.DB, error) {
	h, err := open(Path())
	if err != nil {
		return nil, err
	}
	return h.conn, nil
}

// AgentOpen returns the agent database (plugin data).
func AgentOpen() (*sql.DB, error) {
	h, err := open(AgentPath())
	if err != nil {
		return nil, err
	}
	return h.conn, nil
}

// Gorm returns the GORM handle of the web database. Callers use it for
// models whose secret fields carry the vault:"secret" tag.
func Gorm() (*gorm.DB, error) {
	h, err := open(Path())
	if err != nil {
		return nil, err
	}
	return h.gorm, nil
}

// AgentGorm returns the GORM handle of the agent database.
func AgentGorm() (*gorm.DB, error) {
	h, err := open(AgentPath())
	if err != nil {
		return nil, err
	}
	return h.gorm, nil
}

func open(path string) (*handle, error) {
	openMu.Lock()
	defer openMu.Unlock()
	if h := handles[path]; h != nil {
		return h, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("Datenbankverzeichnis: %w", err)
	}
	gdb, err := gorm.Open(sqlite.Open(sqliteDSN(path)), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("GORM %s: %w", path, err)
	}
	web := path == Path()
	keyPath := security.KeyPath()
	if !web {
		keyPath = AgentKeyPath()
	}
	registerVaultCallbacks(gdb, keyPath)
	conn, err := gdb.DB()
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("Datenbank %s: %w", path, err)
	}
	if err := migrate(conn); err != nil {
		conn.Close()
		return nil, err
	}
	if web {
		// Only the web database holds sealed account secrets.
		if err := sealLegacySecrets(conn); err != nil {
			conn.Close()
			return nil, err
		}
	} else if err := rekeyAgentSecrets(conn, keyPath, security.KeyPath()); err != nil {
		conn.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		conn.Close()
		return nil, err
	}
	// Created by root (agent or CLI) inside the state directory: the file
	// belongs to the web user.
	if err := state.HandOver(path); err != nil {
		conn.Close()
		return nil, err
	}
	h := &handle{conn: conn, gorm: gdb}
	handles[path] = h
	return h, nil
}

func sqliteDSN(path string) string {
	return "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
}

func migrate(conn *sql.DB) error {
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	var current int
	if err := conn.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	for i := current; i < len(migrations); i++ {
		tx, err := conn.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range migrations[i] {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("Migration %d: %w", i+1, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
