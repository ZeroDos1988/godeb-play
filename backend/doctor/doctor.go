// Package doctor runs a read-only health check of the host (godeb-play doctor):
// services, listening ports, firewall, tunnel handshakes, certificates, DNS
// of the mail domains, errors in the journal, updates and disk space. The
// report contains no secrets, so admins can pass it on as is.
package doctor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"godebplay/backend/core"
)

// Level is the weight of a finding.
type Level int

const (
	OK Level = iota
	Info
	Warn
	Fail
)

func (l Level) String() string {
	return [...]string{"OK", "INFO", "WARN", "FAIL"}[l]
}

// Finding is one line of the report.
type Finding struct {
	Area    string
	Level   Level
	Text    string
	Details []string
	Fix     *core.Fix // button on the overview; nil when only a page helps
}

// DNSRecord is the live state of one record a plugin needs.
type DNSRecord struct {
	Name, Type, Status, Expected, Found string
	Fix                                 *core.Fix // publish through the provider, if possible
}

// Env is everything the checks read from the host. Default() fills it with
// the real system; tests replace single functions.
type Env struct {
	Run      func(ctx context.Context, name string, args ...string) core.CommandResult
	ReadFile func(path string) ([]byte, error)
	Glob     func(pattern string) ([]string, error)
	Exists   func(path string) bool
	Disk     func(path string) (used, total uint64, err error)
	IfaceOf  func(ip net.IP) string
	DNS      func(ctx context.Context) ([]DNSRecord, error)
	Now      func() time.Time
	Version  string
	// Databases are the SQLite files this process may check; CheckDB runs
	// PRAGMA quick_check on one (found=false for a missing file).
	Databases []DBFile
	CheckDB   func(ctx context.Context, path string) (found bool, err error)
}

// DBFile is one SQLite database for checkDatabases.
type DBFile struct {
	Name, Path string
}

// Default returns an Env for the running host.
func Default(version string) Env {
	return Env{
		Run:      core.RunQuiet,
		ReadFile: os.ReadFile,
		Glob:     filepath.Glob,
		Exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		Disk:    diskUsage,
		IfaceOf: ifaceOf,
		Now:     time.Now,
		Version: version,
	}
}

// extra are checks of plugins (Register); doctor never imports plugins.
var (
	extraMu sync.Mutex
	extra   []func(context.Context) []Finding
)

// Register adds a plugin check. It runs after the firewall check.
func Register(check func(context.Context) []Finding) {
	extraMu.Lock()
	extra = append(extra, check)
	extraMu.Unlock()
}

func checkRegistered(ctx context.Context, _ Env) []Finding {
	extraMu.Lock()
	list := append([]func(context.Context) []Finding(nil), extra...)
	extraMu.Unlock()
	var out []Finding
	for _, c := range list {
		out = append(out, c(ctx)...)
	}
	return out
}

// Check runs all checks in report order.
func Check(ctx context.Context, env Env) []Finding {
	var out []Finding
	for _, c := range []func(context.Context, Env) []Finding{
		checkVersion, checkServices, checkPorts, checkFirewall, checkRegistered, checkWireGuard,
		checkCerts, checkDNS, checkJournal, checkUpdates, checkReboot, checkDisk, CheckDatabases, checkHardening,
	} {
		out = append(out, c(ctx, env)...)
	}
	return out
}

// CheckOnly runs the given checks, e.g. the web process's own part.
func CheckOnly(ctx context.Context, env Env, checks ...func(context.Context, Env) []Finding) []Finding {
	var out []Finding
	for _, c := range checks {
		out = append(out, c(ctx, env)...)
	}
	return out
}

// Report is the JSON form of a Check for the web UI and /internal/doctor.
type Report struct {
	Findings []ReportFinding `json:"findings"`
	Fails    int             `json:"fails"`
	Warns    int             `json:"warns"`
	Checked  int64           `json:"checked"` // unix seconds
}

// ReportFinding is one Finding without secrets (same fields as the CLI).
type ReportFinding struct {
	Area    string   `json:"area"`
	Level   string   `json:"level"` // OK, INFO, WARN, FAIL
	Text    string   `json:"text"`
	Details []string `json:"details,omitempty"`
	// Page is the plugin page where the finding is fixed, so the overview
	// can link to it. Empty when no page fits (hardening, databases).
	Page string `json:"page,omitempty"`
	// Fix is the one-click action, if the finding has a safe one.
	Fix *core.Fix `json:"fix,omitempty"`
}

// pages maps an area to the plugin whose page deals with it.
var pages = map[string]string{
	"GoDeb":                             "apt",
	"Updates":                           "apt",
	"Dienste":                           "systemd",
	"Offene Ports":                      "ufw",
	"Firewall":                          "ufw",
	"WireGuard":                         "wireguard",
	"Zertifikate":                       "certbot",
	"DNS":                               "domains",
	"Journal (Fehler seit Systemstart)": "logs",
	"Speicher":                          "monitor",
	"Fernzugang":                        "ufw",
	"Neustart":                          "systemd",
}

// NewReport turns Check results into the API payload.
func NewReport(findings []Finding, at time.Time) Report {
	r := Report{Findings: make([]ReportFinding, 0, len(findings)), Checked: at.Unix()}
	r.Add(findings)
	return r
}

// Add appends findings and updates the counters.
func (r *Report) Add(findings []Finding) {
	for _, f := range findings {
		r.Findings = append(r.Findings, ReportFinding{Area: f.Area, Level: f.Level.String(), Text: f.Text, Details: f.Details, Page: pages[f.Area], Fix: f.Fix})
		switch f.Level {
		case Fail:
			r.Fails++
		case Warn:
			r.Warns++
		}
	}
}

// Write prints the report grouped by area and returns the number of
// failures and warnings.
func Write(w io.Writer, findings []Finding) (fails, warns int) {
	area := ""
	for _, f := range findings {
		if f.Area != area {
			area = f.Area
			fmt.Fprintf(w, "== %s\n", area)
		}
		fmt.Fprintf(w, "%-5s %s\n", f.Level, f.Text)
		for _, d := range f.Details {
			fmt.Fprintf(w, "      %s\n", d)
		}
		switch f.Level {
		case Fail:
			fails++
		case Warn:
			warns++
		}
	}
	fmt.Fprintf(w, "\nErgebnis: %d Fehler, %d Warnungen\n", fails, warns)
	return fails, warns
}

func missing(res core.CommandResult) bool {
	return errors.Is(res.Err, exec.ErrNotFound)
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func checkVersion(ctx context.Context, env Env) []Finding {
	const area = "GoDeb"
	f := Finding{Area: area, Level: Info, Text: "Version " + env.Version}
	res := env.Run(ctx, "apt-cache", "policy", "godeb-play")
	if res.Err != nil {
		return []Finding{f}
	}
	installed, candidate := parsePolicy(res.Stdout)
	if candidate != "" && installed != "" && installed != "(none)" && candidate != installed {
		return []Finding{f, {Area: area, Level: Warn, Text: "Update verfügbar: " + installed + " → " + candidate}}
	}
	return []Finding{f}
}

func parsePolicy(out string) (installed, candidate string) {
	for _, l := range lines(out) {
		if v, ok := strings.CutPrefix(l, "Installed:"); ok {
			installed = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "Candidate:"); ok {
			candidate = strings.TrimSpace(v)
		}
	}
	return installed, candidate
}

func checkServices(ctx context.Context, env Env) []Finding {
	const area = "Dienste"
	var out []Finding
	units := []string{"godeb-play", "godeb-play-agent"}
	res := env.Run(ctx, "systemctl", "is-active", units[0], units[1])
	if missing(res) {
		return []Finding{{Area: area, Level: Info, Text: "systemctl nicht gefunden"}}
	}
	states := lines(res.Stdout)
	for i, u := range units {
		state := "unbekannt"
		if i < len(states) {
			state = states[i]
		}
		if state == "active" {
			out = append(out, Finding{Area: area, Level: OK, Text: u + " läuft"})
		} else {
			out = append(out, Finding{Area: area, Level: Fail, Text: u + ": " + state})
		}
	}
	failed := env.Run(ctx, "systemctl", "--failed", "--plain", "--no-legend", "--no-pager")
	var names, others []string
	for _, l := range lines(failed.Stdout) {
		names = append(names, strings.Fields(l)[0])
	}
	// A failed service gets its own line with a restart button; timers,
	// mounts and GoDeb's own units stay in one line without.
	for _, n := range names {
		if !restartable(n) {
			others = append(others, n)
			continue
		}
		out = append(out, Finding{Area: area, Level: Fail, Text: "fehlgeschlagen: " + n, Fix: &core.Fix{
			Action: "restart", Path: "/api/plugins/systemd/action", Body: map[string]string{"unit": n, "action": "restart"},
		}})
	}
	if len(others) > 0 {
		out = append(out, Finding{Area: area, Level: Fail, Text: fmt.Sprintf("%d fehlgeschlagene Units", len(others)), Details: others})
	} else if len(names) == 0 && failed.Err == nil {
		out = append(out, Finding{Area: area, Level: OK, Text: "keine fehlgeschlagenen Units"})
	}
	return out
}

// restartable matches what the systemd plugin may restart.
func restartable(unit string) bool {
	return serviceUnit.MatchString(unit) && unit != "godeb-play.service" && unit != "godeb-play-agent.service"
}

var serviceUnit = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:._@-]{0,120}\.service$`)

// Listener is one listening socket outside loopback.
type Listener struct {
	Proto, Addr, Scope, Process string
	Port                        int
}

// riskyPorts should not be reachable from outside; the firewall may still
// block them, so they are warnings, not failures.
var riskyPorts = map[int]string{
	3306: "MariaDB", 5432: "PostgreSQL", 6379: "Redis", 8080: "GoDeb (HTTP)", 11334: "Rspamd-Weboberfläche",
}

func checkPorts(ctx context.Context, env Env) []Finding {
	const area = "Offene Ports"
	res := env.Run(ctx, "ss", "-H", "-ltnup")
	if res.Err != nil {
		return []Finding{{Area: area, Level: Info, Text: "ss nicht verfügbar"}}
	}
	ls := parseSS(res.Stdout, env.IfaceOf)
	if len(ls) == 0 {
		return []Finding{{Area: area, Level: OK, Text: "nur Loopback"}}
	}
	var out []Finding
	var info []string
	for _, l := range ls {
		desc := fmt.Sprintf("%s %d %s (%s)", l.Proto, l.Port, l.Scope, l.Process)
		switch {
		case l.Process == "godeb-play" && l.Scope == "alle Adressen":
			out = append(out, Finding{Area: area, Level: Warn, Text: "GoDeb lauscht auf allen Adressen: " + desc})
		case riskyPorts[l.Port] != "" && !strings.HasPrefix(l.Scope, "Tunnel"):
			out = append(out, Finding{Area: area, Level: Warn, Text: riskyPorts[l.Port] + " von außen erreichbar? " + desc + " – Firewall prüfen"})
		default:
			info = append(info, desc)
		}
	}
	if len(info) > 0 {
		out = append([]Finding{{Area: area, Level: Info, Text: fmt.Sprintf("%d Ports außerhalb von Loopback", len(info)), Details: info}}, out...)
	}
	return out
}

// parseSS reads `ss -H -ltnup` and drops loopback; IPv4 and IPv6 sockets of
// the same port and process are merged.
func parseSS(out string, ifaceOf func(net.IP) string) []Listener {
	seen := map[string]bool{}
	var res []Listener
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		host := strings.Trim(local[:i], "[]")
		iface := ""
		if h, z, ok := strings.Cut(host, "%"); ok {
			host, iface = h, z
		}
		ip := net.ParseIP(host)
		if iface == "lo" || (ip != nil && ip.IsLoopback()) {
			continue
		}
		scope := ""
		switch {
		case host == "*" || host == "0.0.0.0" || host == "::":
			scope = "alle Adressen"
		default:
			if iface == "" && ip != nil && ifaceOf != nil {
				iface = ifaceOf(ip)
			}
			if strings.HasPrefix(iface, "wg") {
				scope = "Tunnel " + host
			} else {
				scope = host
			}
		}
		proc := "?"
		if len(f) > 6 {
			if _, rest, ok := strings.Cut(strings.Join(f[6:], " "), `(("`); ok {
				proc, _, _ = strings.Cut(rest, `"`)
			}
		}
		if scope == "alle Adressen" {
			key := fmt.Sprintf("%s/%d/%s", f[0], port, proc)
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		res = append(res, Listener{Proto: f[0], Addr: host, Scope: scope, Process: proc, Port: port})
	}
	sort.SliceStable(res, func(a, b int) bool {
		if res[a].Port != res[b].Port {
			return res[a].Port < res[b].Port
		}
		return res[a].Proto < res[b].Proto
	})
	return res
}

func checkFirewall(ctx context.Context, env Env) []Finding {
	const area = "Firewall"
	res := env.Run(ctx, "ufw", "status")
	if missing(res) {
		return []Finding{{Area: area, Level: Warn, Text: "ufw nicht installiert"}}
	}
	if strings.Contains(res.Stdout, "Status: active") {
		return []Finding{{Area: area, Level: OK, Text: "ufw aktiv"}}
	}
	return []Finding{{Area: area, Level: Fail, Text: "ufw nicht aktiv"}}
}

// Peer is the handshake state of one WireGuard peer.
type Peer struct {
	Iface, Key string
	Last       time.Time
}

func checkWireGuard(ctx context.Context, env Env) []Finding {
	const area = "WireGuard"
	res := env.Run(ctx, "wg", "show", "all", "latest-handshakes")
	if missing(res) {
		return []Finding{{Area: area, Level: Info, Text: "WireGuard nicht installiert"}}
	}
	if res.Err != nil {
		return []Finding{{Area: area, Level: Warn, Text: "wg show fehlgeschlagen: " + strings.TrimSpace(res.Stderr)}}
	}
	peers := parseHandshakes(res.Stdout)
	if len(peers) == 0 {
		return []Finding{{Area: area, Level: Info, Text: "keine Peers"}}
	}
	now := env.Now()
	active := 0
	var details []string
	for _, p := range peers {
		state := "noch nie verbunden"
		if !p.Last.IsZero() {
			age := now.Sub(p.Last).Round(time.Second)
			state = "letzter Handshake vor " + age.String()
			if age <= 3*time.Minute {
				active++
			}
		}
		details = append(details, fmt.Sprintf("%s %s…: %s", p.Iface, p.Key, state))
	}
	f := Finding{Area: area, Level: OK, Text: fmt.Sprintf("%d von %d Peers aktiv (Handshake < 3 min)", active, len(peers)), Details: details}
	if active == 0 {
		f.Level = Warn
	}
	return []Finding{f}
}

// parseHandshakes reads `wg show all latest-handshakes`. Public keys are
// shortened to 8 characters; they are not secret, but the report stays
// readable.
func parseHandshakes(out string) []Peer {
	var res []Peer
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		key := f[1]
		if len(key) > 8 {
			key = key[:8]
		}
		p := Peer{Iface: f[0], Key: key}
		if sec, err := strconv.ParseInt(f[2], 10, 64); err == nil && sec > 0 {
			p.Last = time.Unix(sec, 0)
		}
		res = append(res, p)
	}
	return res
}

func checkCerts(_ context.Context, env Env) []Finding {
	const area = "Zertifikate"
	paths, _ := env.Glob("/etc/letsencrypt/live/*/cert.pem")
	if len(paths) == 0 {
		return []Finding{{Area: area, Level: Info, Text: "keine Let's-Encrypt-Zertifikate"}}
	}
	var out []Finding
	now := env.Now()
	for _, p := range paths {
		name := filepath.Base(filepath.Dir(p))
		data, err := env.ReadFile(p)
		if err != nil {
			out = append(out, Finding{Area: area, Level: Warn, Text: name + ": nicht lesbar"})
			continue
		}
		cert, err := parseCert(data)
		if err != nil {
			out = append(out, Finding{Area: area, Level: Warn, Text: name + ": " + err.Error()})
			continue
		}
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		f := Finding{Area: area, Level: OK, Text: fmt.Sprintf("%s gültig bis %s (%d Tage)", name, cert.NotAfter.Format("2006-01-02"), days)}
		switch {
		case days < 0:
			f.Level, f.Text = Fail, fmt.Sprintf("%s abgelaufen seit %s", name, cert.NotAfter.Format("2006-01-02"))
		case days < 14:
			f.Level = Warn
		}
		out = append(out, f)
	}
	return out
}

func parseCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("kein PEM-Zertifikat")
	}
	return x509.ParseCertificate(block.Bytes)
}

func checkDNS(ctx context.Context, env Env) []Finding {
	const area = "DNS"
	if env.DNS == nil {
		return nil
	}
	recs, err := env.DNS(ctx)
	if err != nil {
		return []Finding{{Area: area, Level: Warn, Text: "DNS-Prüfung fehlgeschlagen: " + err.Error()}}
	}
	if len(recs) == 0 {
		return []Finding{{Area: area, Level: Info, Text: "keine DNS-Einträge nötig (kein Mailserver eingerichtet)"}}
	}
	ok := 0
	var out []Finding
	for _, r := range recs {
		if r.Status == "ok" {
			ok++
			continue
		}
		f := Finding{Area: area, Level: Warn, Text: fmt.Sprintf("%s %s: %s", r.Type, r.Name, statusText(r.Status)), Details: []string{"erwartet: " + r.Expected}, Fix: r.Fix}
		if r.Found != "" {
			f.Details = append(f.Details, "gefunden: "+r.Found)
		}
		out = append(out, f)
	}
	return append([]Finding{{Area: area, Level: OK, Text: fmt.Sprintf("%d von %d Einträgen stimmen", ok, len(recs))}}, out...)
}

func statusText(s string) string {
	switch s {
	case "missing":
		return "fehlt"
	case "wrong":
		return "falscher Wert"
	default:
		return "nicht prüfbar"
	}
}

// journalUnits are the services whose errors since boot are listed.
var journalUnits = []string{"godeb-play", "godeb-play-agent", "wg-quick@wg0", "fail2ban"}

func checkJournal(ctx context.Context, env Env) []Finding {
	const area = "Journal (Fehler seit Systemstart)"
	args := []string{"-p", "err", "-b", "--no-pager", "-q", "-o", "short-iso", "-n", "15"}
	for _, u := range journalUnits {
		args = append(args, "-u", u)
	}
	res := env.Run(ctx, "journalctl", args...)
	if missing(res) {
		return nil
	}
	ls := lines(res.Stdout)
	if len(ls) == 0 {
		return []Finding{{Area: area, Level: OK, Text: "keine Fehler"}}
	}
	return []Finding{{Area: area, Level: Warn, Text: fmt.Sprintf("%d Fehlermeldungen (die letzten 15)", len(ls)), Details: ls}}
}

func checkUpdates(ctx context.Context, env Env) []Finding {
	const area = "Updates"
	var out []Finding
	res := env.Run(ctx, "apt", "list", "--upgradable")
	if !missing(res) {
		all, security := ParseUpgradable(res.Stdout)
		switch {
		case len(security) > 0:
			out = append(out, Finding{Area: area, Level: Warn, Text: fmt.Sprintf("%d Sicherheitsupdates ausstehend (insgesamt %d)", len(security), len(all)), Details: security,
				Fix: &core.Fix{Action: "securityUpdates", Path: "/api/plugins/apt/security"}})
		case len(all) > 0:
			out = append(out, Finding{Area: area, Level: Info, Text: fmt.Sprintf("%d Updates verfügbar", len(all))})
		default:
			out = append(out, Finding{Area: area, Level: OK, Text: "System aktuell"})
		}
	}
	return out
}

// RebootPath and RebootCancelPath are the routes of the systemd plugin that
// schedule and cancel a reboot (fix buttons on the overview).
const (
	RebootPath       = "/api/plugins/systemd/reboot"
	RebootCancelPath = "/api/plugins/systemd/reboot/cancel"
)

func checkReboot(ctx context.Context, env Env) []Finding {
	const area = "Neustart"
	if mode, at, ok := ScheduledShutdown(ctx, env.Run); ok {
		text := "Neustart geplant um " + at.Local().Format("15:04")
		if mode != "reboot" {
			text = "Herunterfahren geplant um " + at.Local().Format("15:04")
		}
		return []Finding{{Area: area, Level: Warn, Text: text, Fix: &core.Fix{Action: "rebootCancel", Path: RebootCancelPath}}}
	}
	if env.Exists("/run/reboot-required") {
		return []Finding{{Area: area, Level: Warn, Text: "Neustart nötig (/run/reboot-required)", Fix: &core.Fix{Action: "reboot", Path: RebootPath}}}
	}
	return nil
}

// scheduledPattern matches busctl's view of logind's ScheduledShutdown
// property: (st) "reboot" 1731024000000000.
var scheduledPattern = regexp.MustCompile(`^\(st\) "([a-z-]*)" (\d+)$`)

// ParseScheduledShutdown reads the busctl output of ScheduledShutdown. ok is
// false when nothing is scheduled or the output is not understood.
func ParseScheduledShutdown(out string) (mode string, at time.Time, ok bool) {
	m := scheduledPattern.FindStringSubmatch(strings.TrimSpace(out))
	if m == nil || m[1] == "" {
		return "", time.Time{}, false
	}
	usec, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil || usec <= 0 {
		return "", time.Time{}, false
	}
	return m[1], time.UnixMicro(usec), true
}

// ScheduledShutdown asks logind whether `shutdown -r +N` (or -h) is pending.
func ScheduledShutdown(ctx context.Context, run func(ctx context.Context, name string, args ...string) core.CommandResult) (mode string, at time.Time, ok bool) {
	res := run(ctx, "busctl", "get-property", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ScheduledShutdown")
	if res.Err != nil {
		return "", time.Time{}, false
	}
	return ParseScheduledShutdown(res.Stdout)
}

// ParseUpgradable reads `apt list --upgradable` and returns all package
// names and those coming from a -security suite. Same rule as plugins/apt
// and the monitor Ampel.
func ParseUpgradable(out string) (all, security []string) {
	for _, l := range lines(out) {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		name, suites, ok := strings.Cut(fields[0], "/")
		if !ok {
			continue
		}
		all = append(all, name)
		if strings.Contains(suites, "-security") {
			security = append(security, name)
		}
	}
	return all, security
}

func checkDisk(_ context.Context, env Env) []Finding {
	const area = "Speicher"
	used, total, err := env.Disk("/")
	if err != nil || total == 0 {
		return []Finding{{Area: area, Level: Info, Text: "Belegung von / unbekannt"}}
	}
	pct := int(used * 100 / total)
	f := Finding{Area: area, Level: OK, Text: fmt.Sprintf("/ zu %d %% belegt (%.1f von %.1f GiB)", pct, gib(used), gib(total))}
	switch {
	case pct >= 90:
		f.Level = Fail
	case pct >= 80:
		f.Level = Warn
	}
	return []Finding{f}
}

// checkDatabases runs quick_check on GoDeb's SQLite files. A damaged file
// is a failure: restore the machine from a snapshot (see "Notfall").
func CheckDatabases(ctx context.Context, env Env) []Finding {
	if env.CheckDB == nil {
		return nil
	}
	var out []Finding
	for _, d := range env.Databases {
		found, err := env.CheckDB(ctx, d.Path)
		switch {
		case err != nil:
			out = append(out, Finding{Area: "Datenbanken", Level: Fail, Text: fmt.Sprintf("%s (%s): %v", d.Name, d.Path, err)})
		case found:
			out = append(out, Finding{Area: "Datenbanken", Level: OK, Text: fmt.Sprintf("%s in Ordnung", d.Name)})
		}
	}
	return out
}

// checkHardening only reports; it never changes SSH or unattended-upgrades.
// Password login and root passwords are warnings; unattended-upgrades is
// informational because GoDeb installs security updates itself via apt.
func checkHardening(ctx context.Context, env Env) []Finding {
	const area = "Härtung"
	var out []Finding
	out = append(out, sshFindings(env.Run(ctx, "sshd", "-T"))...)
	out = append(out, unattendedFindings(env.Run(ctx, "systemctl", "is-enabled", "unattended-upgrades.service"))...)
	return out
}

func sshFindings(res core.CommandResult) []Finding {
	const area = "Härtung"
	if missing(res) {
		return []Finding{{Area: area, Level: Info, Text: "sshd nicht gefunden"}}
	}
	if res.Err != nil {
		return []Finding{{Area: area, Level: Info, Text: "sshd -T nicht lesbar"}}
	}
	pass, root := parseSSHD(res.Stdout)
	var out []Finding
	switch pass {
	case "no":
		out = append(out, Finding{Area: area, Level: OK, Text: "SSH nur per Schlüssel (PasswordAuthentication no)"})
	case "yes":
		out = append(out, Finding{Area: area, Level: Warn, Text: "SSH erlaubt Passwort-Login", Details: []string{"PasswordAuthentication yes – in sshd_config.d abschalten, nachdem Schlüssel-Login funktioniert"}})
	default:
		out = append(out, Finding{Area: area, Level: Info, Text: "SSH PasswordAuthentication: " + pass})
	}
	switch root {
	case "prohibit-password", "without-password", "no":
		out = append(out, Finding{Area: area, Level: OK, Text: "Root-SSH ohne Passwort (" + root + ")"})
	case "yes":
		out = append(out, Finding{Area: area, Level: Warn, Text: "Root-SSH mit Passwort erlaubt", Details: []string{"PermitRootLogin yes"}})
	default:
		if root != "" {
			out = append(out, Finding{Area: area, Level: Info, Text: "PermitRootLogin " + root})
		}
	}
	return out
}

func parseSSHD(out string) (passwordAuth, permitRoot string) {
	for _, l := range lines(out) {
		f := strings.Fields(strings.ToLower(l))
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "passwordauthentication":
			passwordAuth = f[1]
		case "permitrootlogin":
			permitRoot = f[1]
		}
	}
	return passwordAuth, permitRoot
}

func unattendedFindings(res core.CommandResult) []Finding {
	const area = "Härtung"
	if missing(res) {
		return []Finding{{Area: area, Level: Info, Text: "unattended-upgrades nicht geprüft (systemctl fehlt)"}}
	}
	state := strings.TrimSpace(res.Stdout)
	if state == "" {
		state = "unbekannt"
	}
	// GoDeb installs security updates itself; this is only a notice.
	if state == "enabled" {
		return []Finding{{Area: area, Level: Info, Text: "unattended-upgrades ist aktiv (zusätzlich zur GoDeb-APT-Automatik)"}}
	}
	return []Finding{{Area: area, Level: Info, Text: "unattended-upgrades: " + state, Details: []string{"GoDeb spielt Sicherheitsupdates über das APT-Plugin ein; unattended-upgrades ist optional"}}}
}

func gib(b uint64) float64 { return float64(b) / (1 << 30) }

func diskUsage(path string) (used, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	return total - free, total, nil
}

func ifaceOf(ip net.IP) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return i.Name
			}
		}
	}
	return ""
}
