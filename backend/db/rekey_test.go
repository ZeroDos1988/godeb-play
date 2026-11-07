package db

import (
	"os"
	"path/filepath"
	"testing"

	"godebplay/backend/security"
)

func TestAgentDatabaseUsesAgentKeyAndRekeysLegacy(t *testing.T) {
	dir := t.TempDir()
	webKey := filepath.Join(dir, "web", "master.key")
	agentKey := filepath.Join(dir, "agent", "master.key")
	agentDB := filepath.Join(dir, "agent", "godeb.db")
	for _, d := range []string{"web", "agent"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GODEB_DB", filepath.Join(dir, "web", "godeb.db"))
	t.Setenv("GODEB_MASTER_KEY", webKey)
	t.Setenv("GODEB_AGENT_DB", agentDB)
	t.Setenv("GODEB_AGENT_MASTER_KEY", "")
	if got := AgentKeyPath(); got != agentKey {
		t.Fatalf("AgentKeyPath = %q", got)
	}

	// An older version sealed this value with the web key.
	legacy, err := security.SealWith(webKey, "old-secret")
	if err != nil {
		t.Fatal(err)
	}
	reopen := func() *handle {
		t.Helper()
		openMu.Lock()
		if h := handles[agentDB]; h != nil {
			h.conn.Close()
			delete(handles, agentDB)
		}
		openMu.Unlock()
		h, err := open(agentDB)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	t.Cleanup(func() {
		openMu.Lock()
		if h := handles[agentDB]; h != nil {
			h.conn.Close()
			delete(handles, agentDB)
		}
		openMu.Unlock()
	})
	conn := reopen().conn
	if _, err := conn.Exec(`CREATE TABLE rekey_samples (id TEXT PRIMARY KEY, secret TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO rekey_samples VALUES ('a', ?), ('b', '')`, legacy); err != nil {
		t.Fatal(err)
	}

	RegisterAgentSecret("rekey_samples", "id", "secret")
	t.Cleanup(func() {
		agentSecretsMu.Lock()
		agentSecrets = agentSecrets[:len(agentSecrets)-1]
		agentSecretsMu.Unlock()
	})

	conn = reopen().conn
	var stored string
	if err := conn.QueryRow(`SELECT secret FROM rekey_samples WHERE id = 'a'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if got, err := security.OpenWith(agentKey, stored); err != nil || got != "old-secret" {
		t.Fatalf("agent key open = %q, %v", got, err)
	}
	if _, err := security.OpenWith(webKey, stored); err == nil {
		t.Fatal("value still opens with the web key")
	}

	// Once migrated, the web key is not needed anymore.
	if err := os.Remove(webKey); err != nil {
		t.Fatal(err)
	}
	if err := rekeyAgentSecrets(conn, agentKey, webKey); err != nil {
		t.Fatalf("rekey without legacy key: %v", err)
	}
}

func TestReadKeyFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(target); err != nil {
		t.Fatalf("regular file: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(link); err == nil {
		t.Fatal("symlink was followed")
	}
}
