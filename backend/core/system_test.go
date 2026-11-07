package core

import "testing"

func TestParseCPUAndDisk(t *testing.T) {
	sample, ok := parseCPULine("cpu  100 0 50 800 50 0 0 0")
	if !ok || sample.total != 1000 || sample.idle != 850 {
		t.Fatalf("cpu = %+v ok=%v", sample, ok)
	}
	if _, ok := parseCPULine("cpu0 1 2 3"); ok {
		t.Fatal("short line accepted")
	}
	used, total, ok := parseDF("Filesystem 1B-blocks Used Available Use% Mounted\n/dev/vda1 1000 250 750 25% /\n")
	if !ok || used != 250 || total != 1000 {
		t.Fatalf("df = %d/%d ok=%v", used, total, ok)
	}
}

func TestParseOSRelease(t *testing.T) {
	in := "# comment\nNAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
	if got := parseOSRelease(in); got != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatalf("got %q", got)
	}
	if got := parseOSRelease("PRETTY_NAME='Debian GNU/Linux'\n"); got != "Debian GNU/Linux" {
		t.Fatalf("got %q", got)
	}
	if got := parseOSRelease("NAME=Debian\n"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestRepoRootFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GODEB_ROOT", dir)
	got, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("got %s", got)
	}
}

func TestCPUPercentIgnoresGuest(t *testing.T) {
	a, _ := parseCPULine("cpu  100 0 100 700 100 0 0 0 50 0")
	b, _ := parseCPULine("cpu  110 0 110 880 100 0 0 0 60 0")
	if a.total != 1000 {
		t.Fatalf("guest counted twice: total = %d", a.total)
	}
	v, ok := cpuPercent(a, b)
	if !ok || v < 9.99 || v > 10.01 {
		t.Fatalf("cpu = %v %v", v, ok)
	}
	if _, ok := cpuPercent(b, a); ok {
		t.Fatal("counter going back must be rejected")
	}
}
