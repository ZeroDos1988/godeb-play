package db

import (
	"database/sql"
	"fmt"

	"godebplay/backend/security"
)

// sealLegacySecrets encrypts sensitive columns that were written before the
// vault existed. Rows that already carry the v1: prefix are left untouched.
func sealLegacySecrets(conn *sql.DB) error {
	if err := sealColumn(conn, "users", "username", "password_hash"); err != nil {
		return err
	}
	if err := sealColumn(conn, "users", "username", "totp_secret"); err != nil {
		return err
	}
	if err := sealColumn(conn, "users", "username", "backup_codes"); err != nil {
		return err
	}
	return sealColumn(conn, "oidc_providers", "id", "client_secret")
}

func sealColumn(conn *sql.DB, table, key, column string) error {
	query := fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s <> ''`, key, column, table, column)
	rows, err := conn.Query(query)
	if err != nil {
		return fmt.Errorf("Secrets lesen (%s.%s): %w", table, column, err)
	}
	defer rows.Close()

	type pair struct{ id, value string }
	pending := make([]pair, 0)
	for rows.Next() {
		var id, value string
		if err := rows.Scan(&id, &value); err != nil {
			return err
		}
		if value == "" || value == "[]" || security.IsSealed(value) {
			continue
		}
		sealed, err := security.Seal(value)
		if err != nil {
			return err
		}
		pending = append(pending, pair{id: id, value: sealed})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	update := fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s = ?`, table, column, key)
	for _, item := range pending {
		if _, err := conn.Exec(update, item.value, item.id); err != nil {
			return fmt.Errorf("Secret schreiben (%s.%s): %w", table, column, err)
		}
	}
	return nil
}
