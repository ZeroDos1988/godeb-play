package apt

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecuritySuites(t *testing.T) {
	out := `Listing...
openssl/trixie-security 3.5.4-1~deb13u2 amd64 [upgradable from: 3.5.4-1~deb13u1]
libssl3t64/trixie-security,trixie-updates 3.5.4-1~deb13u2 amd64 [upgradable from: 3.5.4-1~deb13u1]
bash/trixie 5.2.37-2+b5 amd64 [upgradable from: 5.2.37-2]
godeb/trixie 0.2.5 amd64 [upgradable from: 0.2.4]
`
	pkgs := ParseUpgradable(out)
	if len(pkgs) != 4 || !pkgs[0].Security || !pkgs[1].Security || pkgs[2].Security || pkgs[3].Security {
		t.Fatalf("security flags wrong: %+v", pkgs)
	}
	if got := strings.Join(securityPackages(pkgs), " "); got != "openssl libssl3t64" {
		t.Fatalf("securityPackages = %q", got)
	}
	// Names that are not plain package names never reach apt-get.
	bad := []Package{{Name: "-oAPT::X=1", Security: true}, {Name: "ok", Security: true}}
	if got := securityPackages(bad); len(got) != 1 || got[0] != "ok" {
		t.Fatalf("unchecked name passed: %v", got)
	}
}

func TestSettingsValidation(t *testing.T) {
	if _, err := validSettings(defaultSettings()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 4, 1441} {
		if _, err := validSettings(Settings{Interval: n}); err == nil {
			t.Errorf("interval %d accepted", n)
		}
	}
	d := defaultSettings()
	if !d.AutoCheck || !d.AutoSecurity || d.Interval != 10 {
		t.Fatalf("defaults %+v", d)
	}
}

func TestSchedulerDue(t *testing.T) {
	var s scheduler
	now := time.Now()
	if !s.due(now, 10*time.Minute) {
		t.Fatal("first check must be due")
	}
	s.checked(now)
	if s.due(now.Add(9*time.Minute), 10*time.Minute) || !s.due(now.Add(10*time.Minute), 10*time.Minute) {
		t.Fatal("interval not respected")
	}
}

func TestCappedWriter(t *testing.T) {
	var b bytes.Buffer
	w := &cappedWriter{w: &b, left: 5}
	n, err := w.Write([]byte("abcdefgh"))
	if err != nil || n != 8 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	_, _ = w.Write([]byte("more"))
	if !strings.HasPrefix(b.String(), "abcde") || !strings.Contains(b.String(), "gekürzt") || strings.Contains(b.String(), "more") {
		t.Fatalf("log = %q", b.String())
	}
}

// fakeApt puts apt and apt-get scripts on PATH. apt-get records its
// arguments, so the test sees what would have been installed.
func fakeApt(t *testing.T, list string) string {
	t.Helper()
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("apt-get", `echo "$@" >> "`+calls+`"; echo "apt-get $1 ok"`+"\n")
	write("apt", `cat <<'LIST'
`+list+`LIST
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GODEB_STATE_DIR", t.TempDir())
	return calls
}

func TestRunJobSecurityInstallsOnlySecurity(t *testing.T) {
	calls := fakeApt(t, `Listing...
openssl/trixie-security 3.5.4-1~deb13u2 amd64 [upgradable from: 3.5.4-1~deb13u1]
godeb/trixie 0.2.5 amd64 [upgradable from: 0.2.4]
`)
	if err := RunJob(context.Background(), ActionSecurity, "auto"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(calls)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "update") {
		t.Fatalf("calls = %q", lines)
	}
	if !strings.Contains(lines[1], "install --only-upgrade -- openssl") || strings.Contains(lines[1], "godeb") {
		t.Fatalf("install call = %q", lines[1])
	}
	st, ok := readStatus()
	if !ok || !st.OK || st.Finished == "" || st.Trigger != "auto" || strings.Join(st.Installed, ",") != "openssl" {
		t.Fatalf("status = %+v", st)
	}
	if log := strings.Join(readLog(50), "\n"); !strings.Contains(log, "Sicherheitsupdates installieren: openssl") || !strings.Contains(log, "Fertig.") {
		t.Fatalf("log = %s", log)
	}
}

func TestRunJobUpgradeAndCheck(t *testing.T) {
	calls := fakeApt(t, `Listing...
godeb/trixie 0.2.5 amd64 [upgradable from: 0.2.4]
`)
	if err := RunJob(context.Background(), ActionCheck, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := RunJob(context.Background(), ActionUpgrade, "admin"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(calls)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[2], "--with-new-pkgs upgrade") || !strings.Contains(lines[2], "--force-confold") {
		t.Fatalf("calls = %q", lines)
	}
	if err := RunJob(context.Background(), "rm", "x"); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestRunJobRecordsFailure(t *testing.T) {
	fakeApt(t, "Listing...\n")
	path, err := exec.LookPath("apt-get")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Dir(path)
	_ = os.WriteFile(filepath.Join(bin, "apt-get"), []byte("#!/bin/sh\necho 'E: Could not get lock' >&2\nexit 100\n"), 0o755)
	if err := RunJob(context.Background(), ActionCheck, "auto"); err == nil {
		t.Fatal("failure not reported")
	}
	st, _ := readStatus()
	if st.OK || !strings.Contains(st.Error, "Paketlisten aktualisieren fehlgeschlagen") {
		t.Fatalf("status = %+v", st)
	}
}
