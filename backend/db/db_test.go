package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateIsIdempotentAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "godeb.db")
	t.Setenv("GODEB_DB", path)

	conn, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if again != conn {
		t.Fatal("second Open returned a different pool")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}

	var version int
	if err := conn.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("version = %d, migrations = %d", version, len(migrations))
	}
	for _, table := range []string{"users", "user_settings", "wireguard_peers"} {
		var name string
		err := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s: %v", table, err)
		}
	}
}
