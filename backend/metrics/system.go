package metrics

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"godebplay/backend/core"
)

// procRoot lets tests point the readers at sample files.
var procRoot = "/proc"

func init() {
	RegisterSource("system", systemSource)
	RegisterCheck("system", systemCheck)
	RegisterCheck("units", unitsCheck)
	RegisterCheck("reboot", rebootCheck)
	RegisterCheck("time", timeCheck)
	// "updates" is registered by plugins/apt (needs apt.json and the last
	// godeb-play-apt status to decide whether pending security updates warn).
}

var (
	cpuMu   sync.Mutex
	cpuPrev cpuTimes
)

type cpuTimes struct{ total, idle, iowait uint64 }

func systemSource(ctx context.Context) []Sample {
	var out []Sample
	if t, ok := readCPUTimes(); ok {
		cpuMu.Lock()
		prev := cpuPrev
		cpuPrev = t
		cpuMu.Unlock()
		if prev.total > 0 && t.total > prev.total {
			dt := float64(t.total - prev.total)
			out = append(out,
				Sample{Series: "cpu", Value: clampPct(100 * (1 - float64(t.idle+t.iowait-prev.idle-prev.iowait)/dt)), Unit: "%", Label: "CPU"},
				Sample{Series: "cpu.iowait", Value: clampPct(100 * float64(t.iowait-prev.iowait) / dt), Unit: "%", Label: "Warten auf I/O"},
			)
		}
	}
	if m, ok := readMeminfo(); ok && m["MemTotal"] > 0 {
		total, avail := m["MemTotal"], m["MemAvailable"]
		out = append(out, Sample{Series: "mem", Value: clampPct(100 * float64(total-min(avail, total)) / float64(total)), Unit: "%", Label: "RAM"})
		if st := m["SwapTotal"]; st > 0 {
			out = append(out, Sample{Series: "swap", Value: clampPct(100 * float64(st-min(m["SwapFree"], st)) / float64(st)), Unit: "%", Label: "Swap"})
		}
	}
	if l, ok := readLoad(); ok {
		out = append(out, Sample{Series: "load1", Value: l, Label: "Last (1 min)"})
	}
	for _, m := range realMounts() {
		if used, ok := diskUsage(m); ok {
			out = append(out, Sample{Series: "disk:" + seriesPart(m), Value: used, Unit: "%", Label: "Platte " + m})
		}
	}
	for name, c := range readNetDev() {
		out = append(out,
			Sample{Series: "net:" + name + ":rx", Value: float64(c[0]), Counter: true, Unit: "B/s", Label: name + " empfangen"},
			Sample{Series: "net:" + name + ":tx", Value: float64(c[1]), Counter: true, Unit: "B/s", Label: name + " gesendet"},
		)
	}
	for dev, c := range readDiskstats() {
		out = append(out,
			Sample{Series: "io:" + dev + ":read", Value: float64(c[0]), Counter: true, Unit: "B/s", Label: dev + " lesen"},
			Sample{Series: "io:" + dev + ":write", Value: float64(c[1]), Counter: true, Unit: "B/s", Label: dev + " schreiben"},
		)
	}
	return out
}

func clampPct(v float64) float64 {
	return max(0, min(100, v))
}

func readCPUTimes() (cpuTimes, bool) {
	raw, err := os.ReadFile(procRoot + "/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	f := strings.Fields(line)
	if len(f) < 6 || f[0] != "cpu" {
		return cpuTimes{}, false
	}
	var t cpuTimes
	// user nice system idle iowait irq softirq steal (guest is in user).
	for i, s := range f[1:min(len(f), 9)] {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		t.total += n
		switch i {
		case 3:
			t.idle = n
		case 4:
			t.iowait = n
		}
	}
	return t, true
}

func readMeminfo() (map[string]uint64, bool) {
	raw, err := os.ReadFile(procRoot + "/meminfo")
	if err != nil {
		return nil, false
	}
	m := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
			m[strings.TrimSuffix(f[0], ":")] = v * 1024
		}
	}
	return m, true
}

func readLoad() (float64, bool) {
	raw, err := os.ReadFile(procRoot + "/loadavg")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}

var diskFS = map[string]bool{"ext4": true, "ext3": true, "xfs": true, "btrfs": true, "f2fs": true, "zfs": true}

// realMounts lists mount points of disk file systems, each device once.
func realMounts() []string {
	raw, err := os.ReadFile(procRoot + "/mounts")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !diskFS[f[2]] || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		out = append(out, unescapeMount(f[1]))
	}
	return out
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(s)
}

func diskUsage(path string) (float64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0, false
	}
	total := float64(st.Blocks) * float64(st.Bsize)
	free := float64(st.Bavail) * float64(st.Bsize)
	used := total - float64(st.Bfree)*float64(st.Bsize)
	if used+free <= 0 {
		return 0, false
	}
	// Like df: used / (used + available to users).
	return clampPct(100 * used / (used + free)), true
}

// seriesPart maps a free-form name (mount point, peer) into the series
// alphabet.
func seriesPart(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '/', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

// SeriesPart is seriesPart for plugins that build series names.
func SeriesPart(s string) string { return seriesPart(s) }

// readNetDev returns rx/tx byte counters per interface except loopback.
func readNetDev() map[string][2]uint64 {
	raw, err := os.ReadFile(procRoot + "/net/dev")
	if err != nil {
		return nil
	}
	out := map[string][2]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if name == "lo" || len(f) < 9 || !validSeries("net:"+seriesPart(name)) {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[seriesPart(name)] = [2]uint64{rx, tx}
	}
	return out
}

var wholeDisk = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+)$`)

// readDiskstats returns read/write byte counters of whole disks.
func readDiskstats() map[string][2]uint64 {
	raw, err := os.ReadFile(procRoot + "/diskstats")
	if err != nil {
		return nil
	}
	out := map[string][2]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || !wholeDisk.MatchString(f[2]) {
			continue
		}
		rd, err1 := strconv.ParseUint(f[5], 10, 64)
		wr, err2 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[f[2]] = [2]uint64{rd * 512, wr * 512}
	}
	return out
}

// systemCheck flags full disks, memory pressure and a long overload.
func systemCheck(ctx context.Context) []Finding {
	var out []Finding
	for _, m := range realMounts() {
		used, ok := diskUsage(m)
		if !ok {
			continue
		}
		f := Finding{ID: "disk:" + seriesPart(m), Detail: fmt.Sprintf("%s ist zu %.0f %% belegt", m, used)}
		switch {
		case used >= 95:
			f.Status, f.Title = StatusCritical, "Platte fast voll: "+m
		case used >= 85:
			f.Status, f.Title = StatusWarning, "Platte wird voll: "+m
		default:
			continue
		}
		out = append(out, f)
	}
	if m, ok := readMeminfo(); ok && m["MemTotal"] > 0 {
		avail := 100 * float64(m["MemAvailable"]) / float64(m["MemTotal"])
		if avail < 5 {
			out = append(out, Finding{ID: "mem", Status: StatusCritical, Title: "Arbeitsspeicher fast erschöpft", Detail: fmt.Sprintf("nur noch %.0f %% frei", avail)})
		} else if avail < 10 {
			out = append(out, Finding{ID: "mem", Status: StatusWarning, Title: "Arbeitsspeicher knapp", Detail: fmt.Sprintf("nur noch %.0f %% frei", avail)})
		}
	}
	if l, ok := readLoad15(); ok {
		cores := float64(runtime.NumCPU())
		if l > 2*cores {
			out = append(out, Finding{ID: "load", Status: StatusWarning, Title: "Server dauerhaft überlastet", Detail: fmt.Sprintf("Last %.1f über 15 Minuten bei %d Kernen", l, int(cores))})
		}
	}
	return out
}

func readLoad15() (float64, bool) {
	raw, err := os.ReadFile(procRoot + "/loadavg")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(raw))
	if len(f) < 3 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[2], 64)
	return v, err == nil
}

// unitsCheck reports failed systemd units.
func unitsCheck(ctx context.Context) []Finding {
	out, env := core.ReadCommand(ctx, "", "systemctl", "--failed", "--plain", "--no-legend", "--no-pager")
	if env.Mocked {
		return nil
	}
	return ParseFailedUnits(out)
}

// ParseFailedUnits turns `systemctl --failed --plain --no-legend` into findings.
func ParseFailedUnits(out string) []Finding {
	var res []Finding
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.Contains(f[0], ".") {
			continue
		}
		res = append(res, Finding{ID: "unit:" + f[0], Status: StatusCritical, Title: "Dienst ausgefallen: " + f[0], Detail: "systemctl status " + f[0]})
	}
	return res
}

var rebootFile = "/run/reboot-required"

func rebootCheck(ctx context.Context) []Finding {
	if _, err := os.Stat(rebootFile); err != nil {
		return nil
	}
	detail := "Nach Updates (meist Kernel) wartet ein Neustart."
	if raw, err := os.ReadFile(rebootFile + ".pkgs"); err == nil {
		pkgs := strings.Fields(string(raw))
		if len(pkgs) > 0 {
			detail += " Pakete: " + strings.Join(pkgs[:min(len(pkgs), 5)], ", ")
		}
	}
	return []Finding{{ID: "reboot", Status: StatusWarning, Title: "Neustart erforderlich", Detail: detail}}
}

func timeCheck(ctx context.Context) []Finding {
	out, env := core.ReadCommand(ctx, "", "timedatectl", "show", "--property=NTPSynchronized", "--value")
	if env.Mocked {
		return nil
	}
	if strings.TrimSpace(out) == "no" {
		return []Finding{{ID: "time", Status: StatusWarning, Title: "Uhrzeit nicht synchronisiert", Detail: "timedatectl: NTPSynchronized=no. 2FA-Codes und Zertifikate hängen an der Uhr."}}
	}
	return nil
}
