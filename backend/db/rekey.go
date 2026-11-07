package db

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	"godebplay/backend/security"
)

type agentSecret struct{ table, key, column string }

var (
	agentSecretsMu sync.Mutex
	agentSecrets   []agentSecret
)

// RegisterAgentSecret names a sealed column of the agent database (a
// vault:"secret" field). Plugins call it from init(), so values sealed with
// the web key by older versions get re-sealed with the agent key.
func RegisterAgentSecret(table, key, column string) {
	agentSecretsMu.Lock()
	agentSecrets = append(agentSecrets, agentSecret{table, key, column})
	agentSecretsMu.Unlock()
}

// rekeyAgentSecrets re-seals registered agent columns that do not open with
// the agent key but do with legacyKeyPath (the web key, which versions up
// to 0.2.7 used for plugin secrets). The legacy key is read only while such
// values exist, read-only, and never through a symlink.
func rekeyAgentSecrets(conn *sql.DB, agentKeyPath, legacyKeyPath string) error {
	if legacyKeyPath == "" || legacyKeyPath == agentKeyPath {
		return nil
	}
	agentSecretsMu.Lock()
	cols := append([]agentSecret(nil), agentSecrets...)
	agentSecretsMu.Unlock()

	var legacy []byte
	for _, c := range cols {
		rows, err := conn.Query(fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s LIKE 'v1:%%'`, c.key, c.column, c.table, c.column))
		if err != nil {
			if strings.Contains(err.Error(), "no such table") {
				continue
			}
			return fmt.Errorf("Secrets lesen (%s.%s): %w", c.table, c.column, err)
		}
		type pair struct{ id, value string }
		var pending []pair
		for rows.Next() {
			var id, value string
			if err := rows.Scan(&id, &value); err != nil {
				rows.Close()
				return err
			}
			if _, err := security.OpenWith(agentKeyPath, value); err == nil {
				continue
			}
			if legacy == nil {
				if legacy, err = readKeyFile(legacyKeyPath); err != nil {
					rows.Close()
					return fmt.Errorf("Alter Schlüssel für %s.%s: %w", c.table, c.column, err)
				}
			}
			plain, err := security.OpenWithKey(legacy, value)
			if err != nil {
				rows.Close()
				return fmt.Errorf("%s.%s (%s) lässt sich mit keinem Schlüssel öffnen: %w", c.table, c.column, id, err)
			}
			sealed, err := security.SealWith(agentKeyPath, plain)
			if err != nil {
				rows.Close()
				return err
			}
			pending = append(pending, pair{id, sealed})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, p := range pending {
			if _, err := conn.Exec(fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s = ?`, c.table, c.column, c.key), p.value, p.id); err != nil {
				return fmt.Errorf("Secret schreiben (%s.%s): %w", c.table, c.column, err)
			}
		}
	}
	return nil
}

// readKeyFile reads an existing 32-byte key without following symlinks and
// without creating it.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("keine normale Datei")
	}
	key, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, security.ErrKeyLength
	}
	return key, nil
}
