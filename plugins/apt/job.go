package apt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"godebplay/backend/core"
)

// Every apt run (scheduled check, security updates, full upgrade) runs as
// the transient unit godeb-play-apt.service, started with systemd-run. Upgrading
// the godeb package restarts godeb-play-agent.service; a child of the agent
// would be killed in the middle of dpkg. The unit runs `godeb-play apt-run` and
// survives that restart, and so do its log and status, which it keeps in
// the agent's state directory (root only).
const unitName = "godeb-play-apt"

// Actions of `godeb-play apt-run`.
const (
	ActionCheck    = "check"    // apt-get update
	ActionSecurity = "security" // update, then install pending security updates
	ActionUpgrade  = "upgrade"  // update, then upgrade everything
)

var actions = map[string]bool{ActionCheck: true, ActionSecurity: true, ActionUpgrade: true}

// packageName is a Debian package name as apt prints it.
var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

const (
	updateTimeout  = 10 * time.Minute
	installTimeout = 60 * time.Minute
	maxLogBytes    = 256 << 10
)

// Status is the result of the last run, written by `godeb-play apt-run`.
type Status struct {
	Action    string   `json:"action"`
	Trigger   string   `json:"trigger"` // auto or the user who started it
	Started   string   `json:"started"`
	Finished  string   `json:"finished,omitempty"`
	OK        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
	Installed []string `json:"installed,omitempty"`
}

// stateDir is /var/lib/godeb-play-agent/apt, or apt below GODEB_STATE_DIR in
// development.
func stateDir() string {
	if d := strings.TrimSpace(os.Getenv("GODEB_STATE_DIR")); d != "" {
		return filepath.Join(d, "apt")
	}
	return "/var/lib/godeb-play-agent/apt"
}

func statusPath() string { return filepath.Join(stateDir(), "status.json") }
func logPath() string    { return filepath.Join(stateDir(), "apt.log") }

func readStatus() (Status, bool) {
	var s Status
	data, err := os.ReadFile(statusPath())
	if err != nil || json.Unmarshal(data, &s) != nil {
		return s, false
	}
	return s, true
}

func writeStatus(s Status) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := statusPath() + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statusPath())
}

// readLog returns the last lines of the log of the last run.
func readLog(lines int) []string {
	data, err := os.ReadFile(logPath())
	if err != nil {
		return []string{}
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return all
}

// RunJob is `godeb-play apt-run <action>`: it runs inside godeb-play-apt.service as
// root and records log and status for the agent.
func RunJob(ctx context.Context, action, trigger string) error {
	if !actions[action] {
		return fmt.Errorf("unbekannte Aktion %q", action)
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	log := &cappedWriter{w: logFile, left: maxLogBytes}

	st := Status{Action: action, Trigger: trigger, Started: now()}
	if err := writeStatus(st); err != nil {
		return err
	}
	st.Installed, err = runAction(ctx, action, log)
	st.Finished, st.OK = now(), err == nil
	if err != nil {
		st.Error = err.Error()
		fmt.Fprintf(log, "FEHLER: %s\n", err)
	} else {
		fmt.Fprintln(log, "Fertig.")
	}
	if werr := writeStatus(st); werr != nil {
		return errors.Join(err, werr)
	}
	return err
}

func runAction(ctx context.Context, action string, log io.Writer) ([]string, error) {
	if err := step(ctx, log, updateTimeout, "Paketlisten aktualisieren", "apt-get", "-q", "-o", "DPkg::Lock::Timeout=300", "update"); err != nil {
		return nil, err
	}
	switch action {
	case ActionSecurity:
		pending := securityPackages(upgradable(ctx))
		if len(pending) == 0 {
			fmt.Fprintln(log, "Keine Sicherheitsupdates ausstehend.")
			return nil, nil
		}
		args := append(installArgs("install", "--only-upgrade"), "--")
		args = append(args, pending...)
		return pending, step(ctx, log, installTimeout, "Sicherheitsupdates installieren: "+strings.Join(pending, " "), "apt-get", args...)
	case ActionUpgrade:
		pending := names(upgradable(ctx))
		if len(pending) == 0 {
			fmt.Fprintln(log, "Alles aktuell.")
			return nil, nil
		}
		return pending, step(ctx, log, installTimeout, "Alle Pakete aktualisieren", "apt-get", installArgs("--with-new-pkgs", "upgrade")...)
	}
	return nil, nil
}

// installArgs keeps changed configuration files and never asks: the run
// has no terminal.
func installArgs(extra ...string) []string {
	return append([]string{"-q", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "-o", "DPkg::Lock::Timeout=300"}, extra...)
}

func step(ctx context.Context, log io.Writer, timeout time.Duration, title, name string, args ...string) error {
	fmt.Fprintf(log, "==> %s\n$ %s %s\n", title, name, strings.Join(args, " "))
	res := core.RunTimeout(ctx, timeout, name, args...)
	io.WriteString(log, res.Stdout)
	io.WriteString(log, res.Stderr)
	if res.Err != nil {
		return fmt.Errorf("%s fehlgeschlagen: %s", title, firstLine(res.Detail()))
	}
	return nil
}

func upgradable(ctx context.Context) []Package {
	res := core.Run(ctx, "apt", "list", "--upgradable")
	if res.Err != nil {
		return nil
	}
	return ParseUpgradable(res.Stdout)
}

// securityPackages are the upgradable packages whose candidate comes from
// a security suite (trixie-security), the same rule Debian's own
// security announcements use.
func securityPackages(pkgs []Package) []string {
	out := []string{}
	for _, p := range pkgs {
		if p.Security && packageName.MatchString(p.Name) {
			out = append(out, p.Name)
		}
	}
	return dedupe(out)
}

func names(pkgs []Package) []string {
	out := []string{}
	for _, p := range pkgs {
		if packageName.MatchString(p.Name) {
			out = append(out, p.Name)
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// cappedWriter stops writing after a byte budget, so a huge upgrade log
// cannot fill the disk.
type cappedWriter struct {
	w    io.Writer
	left int
	cut  bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.left <= 0 {
		if !c.cut {
			c.cut = true
			_, _ = io.WriteString(c.w, "\n[… Log gekürzt …]\n")
		}
		return len(p), nil
	}
	n := len(p)
	if n > c.left {
		p = p[:c.left]
	}
	_, err := c.w.Write(p)
	c.left -= len(p)
	return n, err
}

// startUnit starts `godeb-play apt-run <action>` as godeb-play-apt.service. Only one
// run at a time; apt itself would refuse a second one anyway.
func startUnit(ctx context.Context, action, trigger string) error {
	if !actions[action] {
		return fmt.Errorf("unbekannte Aktion %q", action)
	}
	if unitActive(ctx) {
		return errors.New("Es läuft bereits eine APT-Aktion")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{
		"--unit=" + unitName, "--collect", "--quiet",
		"--description=GoDeb APT (" + action + ")",
		"--property=Type=exec",
		"--setenv=DEBIAN_FRONTEND=noninteractive",
		"--setenv=UCF_FORCE_CONFFOLD=1",
	}
	if d := strings.TrimSpace(os.Getenv("GODEB_STATE_DIR")); d != "" {
		args = append(args, "--setenv=GODEB_STATE_DIR="+d)
	}
	args = append(args, "--", exe, "apt-run", action, "--trigger", trigger)
	if res := core.RunAdmin(ctx, "systemd-run", args...); res.Err != nil {
		return errors.New("systemd-run: " + firstLine(res.Detail()))
	}
	return nil
}

func unitActive(ctx context.Context) bool {
	res := core.RunQuiet(ctx, "systemctl", "is-active", "--quiet", unitName+".service")
	return res.Err == nil
}
