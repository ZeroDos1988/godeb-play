package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"godebplay/backend/security"
)

type vaultSample struct {
	ID     string `gorm:"primaryKey"`
	Secret string `gorm:"column:secret" vault:"secret"`
	Note   string `gorm:"column:note"`
}

func (vaultSample) TableName() string { return "vault_samples" }

func TestGormVaultHookRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GODEB_DB", filepath.Join(dir, "godeb.db"))
	t.Setenv("GODEB_MASTER_KEY", filepath.Join(dir, "master.key"))

	gdb, err := Gorm()
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(&vaultSample{}); err != nil {
		t.Fatal(err)
	}
	row := vaultSample{ID: "oidc", Secret: "client-secret", Note: "visible"}
	if err := gdb.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Secret != "client-secret" {
		t.Fatalf("in-memory secret after create = %q", row.Secret)
	}

	var stored string
	if err := gdb.Raw(`SELECT secret FROM vault_samples WHERE id = ?`, "oidc").Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if !security.IsSealed(stored) || strings.Contains(stored, "client-secret") {
		t.Fatalf("stored = %q", stored)
	}
	raw, err := os.ReadFile(os.Getenv("GODEB_DB"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "client-secret") {
		t.Fatal("plaintext secret is in the database file")
	}

	var loaded vaultSample
	if err := gdb.First(&loaded, "id = ?", "oidc").Error; err != nil {
		t.Fatal(err)
	}
	if loaded.Secret != "client-secret" || loaded.Note != "visible" {
		t.Fatalf("loaded = %+v", loaded)
	}

	loaded.Secret = "rotated-secret"
	if err := gdb.Save(&loaded).Error; err != nil {
		t.Fatal(err)
	}
	if loaded.Secret != "rotated-secret" {
		t.Fatalf("in-memory after save = %q", loaded.Secret)
	}
	var again vaultSample
	if err := gdb.First(&again, "id = ?", "oidc").Error; err != nil {
		t.Fatal(err)
	}
	if again.Secret != "rotated-secret" {
		t.Fatalf("again = %+v", again)
	}
}
