package systemd

import (
	"bufio"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
)

// catalog is the curated list of server services shown first, like the
// services page of HestiaCP. Only units that exist on the host appear.
var catalog = []catalogEntry{
	{"godeb-play.service", "godeb", "panel"},
	{"godeb-play-agent.service", "godebAgent", "panel"},
	{"ssh.service", "ssh", "system"},
	{"cron.service", "cron", "system"},
	{"systemd-timesyncd.service", "timesync", "system"},
	{"chrony.service", "timesync", "system"},
	{"ufw.service", "ufw", "security"},
	{"fail2ban.service", "fail2ban", "security"},
	{"wg-quick@wg0.service", "wireguard", "network"},
}

type catalogEntry struct {
	Unit  string
	Key   string // i18n key for name and description
	Group string
}

// critical units cut the admin off when stopped (SSH, the tunnel the UI
// is reached through) or open the host (firewall). The UI asks first.
var critical = map[string]bool{"ssh.service": true, "wg-quick@wg0.service": true, "ufw.service": true}

// ServerInfo is the head of the services page.
type ServerInfo struct {
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	Kernel   string    `json:"kernel"`
	Uptime   int64     `json:"uptime"` // seconds
	Load     []float64 `json:"load"`
	CPUs     int       `json:"cpus"`
	MemTotal int64     `json:"memTotal"`
	MemUsed  int64     `json:"memUsed"`
}

// ServiceView is one unit of the curated list.
type ServiceView struct {
	Unit     string  `json:"unit"`
	Key      string  `json:"key"`
	Group    string  `json:"group"`
	Name     string  `json:"name"` // systemd description, fallback for unknown keys
	Active   string  `json:"active"`
	Sub      string  `json:"sub"`
	Enabled  string  `json:"enabled"`
	Since    int64   `json:"since,omitempty"` // unix seconds the unit became active
	Memory   int64   `json:"memory"`          // bytes, -1 unknown
	CPU      float64 `json:"cpu"`             // percent of one core since the last poll, -1 unknown
	Critical bool    `json:"critical,omitempty"`
	Locked   bool    `json:"locked,omitempty"` // no actions (GoDeb itself)
}

type overviewResponse struct {
	core.CommandEnvelope
	Server   ServerInfo    `json:"server"`
	Services []ServiceView `json:"services"`
}

func handleOverview(w http.ResponseWriter, r *http.Request) {
	units := []string{}
	keys := map[string]catalogEntry{}
	for _, c := range catalog {
		units = append(units, c.Unit)
		keys[c.Unit] = c
	}
	args := append([]string{"show", "--timestamp=unix", "--property=" + strings.Join(showProps, ",")}, units...)
	out, env := core.ReadCommand(r.Context(), sampleShow, "systemctl", args...)
	env.Command = []string{"systemctl", "show", "…"}
	views := []ServiceView{}
	now := time.Now()
	for _, u := range ParseShow(out) {
		c, ok := keys[u["Id"]]
		if !ok || u["LoadState"] != "loaded" {
			continue
		}
		v := ServiceView{
			Unit: c.Unit, Key: c.Key, Group: c.Group, Name: u["Description"],
			Active: u["ActiveState"], Sub: u["SubState"], Enabled: u["UnitFileState"],
			Memory: -1, CPU: -1, Critical: critical[c.Unit], Locked: !validUnit(c.Unit),
		}
		if v.Active == "active" {
			v.Since = unixStamp(u["ActiveEnterTimestamp"])
			if m, err := strconv.ParseInt(u["MemoryCurrent"], 10, 64); err == nil {
				v.Memory = m
			}
			if n, err := strconv.ParseInt(u["CPUUsageNSec"], 10, 64); err == nil {
				v.CPU = cpuSamples.percent(c.Unit, n, now)
			}
		}
		views = append(views, v)
	}
	order := map[string]int{}
	for i, c := range catalog {
		order[c.Unit] = i
	}
	sort.SliceStable(views, func(i, j int) bool {
		oi, iok := order[views[i].Unit]
		oj, jok := order[views[j].Unit]
		if iok != jok {
			return iok
		}
		if iok {
			return oi < oj
		}
		return views[i].Unit < views[j].Unit
	})
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, overviewResponse{CommandEnvelope: env, Server: serverInfo(), Services: views})
}

var showProps = []string{"Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "Description", "ActiveEnterTimestamp", "MemoryCurrent", "CPUUsageNSec"}

// ParseShow splits `systemctl show` output for several units (blocks
// separated by empty lines) into property maps.
func ParseShow(out string) []map[string]string {
	units := []map[string]string{}
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			units = append(units, cur)
			cur = map[string]string{}
		}
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	flush()
	return units
}

// unixStamp reads "@1761552721" (systemctl --timestamp=unix).
func unixStamp(v string) int64 {
	n, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(v), "@"), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// cpuSampler turns the cumulative CPUUsageNSec into a percentage between
// two polls of the page.
type cpuSampler struct {
	mu   sync.Mutex
	last map[string]cpuSample
}

type cpuSample struct {
	nsec int64
	at   time.Time
}

var cpuSamples = cpuSampler{last: map[string]cpuSample{}}

func (s *cpuSampler) percent(unit string, nsec int64, now time.Time) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.last[unit]
	s.last[unit] = cpuSample{nsec, now}
	elapsed := now.Sub(prev.at)
	// Too close or too old to mean "now"; a restart resets the counter.
	if !ok || elapsed < time.Second || elapsed > 10*time.Minute || nsec < prev.nsec {
		return -1
	}
	return float64(nsec-prev.nsec) / float64(elapsed.Nanoseconds()) * 100
}

func serverInfo() ServerInfo {
	info := ServerInfo{Load: []float64{}}
	info.Hostname, _ = os.Hostname()
	info.OS = osRelease()
	info.Kernel = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
	if f := strings.Fields(readFile("/proc/uptime")); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			info.Uptime = int64(v)
		}
	}
	for _, f := range strings.Fields(readFile("/proc/loadavg")) {
		if len(info.Load) == 3 {
			break
		}
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			info.Load = append(info.Load, v)
		}
	}
	for _, line := range strings.Split(readFile("/proc/cpuinfo"), "\n") {
		if strings.HasPrefix(line, "processor") {
			info.CPUs++
		}
	}
	mem := map[string]int64{}
	for _, line := range strings.Split(readFile("/proc/meminfo"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				n, _ := strconv.ParseInt(f[0], 10, 64)
				mem[k] = n * 1024
			}
		}
	}
	info.MemTotal = mem["MemTotal"]
	if avail, ok := mem["MemAvailable"]; ok {
		info.MemUsed = info.MemTotal - avail
	}
	return info
}

func osRelease() string {
	for _, line := range strings.Split(readFile("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

const sampleShow = `Id=godeb-play.service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Description=GoDeb web interface
ActiveEnterTimestamp=@1761552000
MemoryCurrent=31457280
CPUUsageNSec=4200000000

Id=ssh.service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Description=OpenBSD Secure Shell server
ActiveEnterTimestamp=@1761500000
MemoryCurrent=6291456
CPUUsageNSec=900000000

Id=fail2ban.service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Description=Fail2Ban Service
ActiveEnterTimestamp=@1761500100
MemoryCurrent=41943040
CPUUsageNSec=12000000000

Id=postfix.service
LoadState=not-found
ActiveState=inactive
SubState=dead
UnitFileState=
Description=postfix.service
ActiveEnterTimestamp=
MemoryCurrent=[not set]
CPUUsageNSec=[not set]
`
