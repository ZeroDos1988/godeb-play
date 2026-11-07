package core

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	fallbackHostname = "debian"
	fallbackOS       = "Debian GNU/Linux 13 (trixie)"
	fallbackKernel   = "6.12.0-amd64"
)

// System is a snapshot gathered from hostname, uname and /etc/os-release.
type System struct {
	Hostname  string  `json:"hostname"`
	OS        string  `json:"os"`
	Kernel    string  `json:"kernel"`
	CPU       float64 `json:"cpu"`
	MemUsed   uint64  `json:"memUsed"`
	MemTotal  uint64  `json:"memTotal"`
	DiskUsed  uint64  `json:"diskUsed"`
	DiskTotal uint64  `json:"diskTotal"`
	Mocked    bool    `json:"mocked"`
	Detail    string  `json:"detail,omitempty"`
}

// CollectSystem reads host identity. Missing commands or files fall back to
// Debian sample values and set Mocked.
func CollectSystem(ctx context.Context) System {
	info := System{}
	var notes []string

	host, hostEnv := ReadCommand(ctx, fallbackHostname+"\n", "hostname")
	info.Hostname = firstLine(host)
	if hostEnv.Mocked {
		info.Mocked = true
		notes = append(notes, "hostname: "+hostEnv.Detail)
	}
	if info.Hostname == "" {
		info.Hostname = fallbackHostname
		info.Mocked = true
	}

	kernel, kernelEnv := ReadCommand(ctx, fallbackKernel+"\n", "uname", "-r")
	info.Kernel = firstLine(kernel)
	if kernelEnv.Mocked {
		info.Mocked = true
		notes = append(notes, "uname: "+kernelEnv.Detail)
	}
	if info.Kernel == "" {
		info.Kernel = fallbackKernel
		info.Mocked = true
	}

	raw, err := os.ReadFile("/etc/os-release")
	pretty := ""
	if err != nil {
		info.Mocked = true
		notes = append(notes, "/etc/os-release: "+err.Error())
	} else {
		pretty = parseOSRelease(string(raw))
		if pretty == "" {
			info.Mocked = true
			notes = append(notes, "/etc/os-release: PRETTY_NAME fehlt")
		}
	}
	if pretty == "" {
		pretty = fallbackOS
	}
	info.OS = pretty
	collectResources(ctx, &info, &notes)
	if len(notes) > 0 {
		info.Detail = strings.Join(notes, "; ")
	}
	return info
}

func collectResources(ctx context.Context, info *System, notes *[]string) {
	if used, total, ok := readMemory(); ok {
		info.MemUsed = used
		info.MemTotal = total
	}
	info.CPU = readCPU(ctx)
	out, env := ReadCommand(ctx, "", "df", "-P", "-B1", "/")
	used, total, ok := parseDF(out)
	if env.Mocked || !ok {
		info.Mocked = true
		if env.Detail != "" {
			*notes = append(*notes, "df: "+env.Detail)
		}
		return
	}
	info.DiskUsed = used
	info.DiskTotal = total
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func readMemory() (used, total uint64, ok bool) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var memTotal, available uint64
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			memTotal = value * 1024
		case "MemAvailable:":
			available = value * 1024
		}
	}
	if memTotal == 0 {
		return 0, 0, false
	}
	if available > memTotal {
		available = memTotal
	}
	return memTotal - available, memTotal, true
}

// cpuState keeps the previous /proc/stat reading, so a request measures the
// CPU over the time since the last one (the overview polls every few
// seconds). A short probe only runs for the first request or after a long
// pause, and then over a full second: a 200 ms probe mostly measured the
// page load itself (parallel requests starting wg and fail2ban-client).
var cpuState struct {
	sync.Mutex
	prev cpuSample
	at   time.Time
}

const (
	cpuMinWindow = time.Second
	cpuMaxAge    = 5 * time.Minute
)

func readCPU(ctx context.Context) float64 {
	now, ok := readCPUSample()
	if !ok {
		return 0
	}
	cpuState.Lock()
	prev, at := cpuState.prev, cpuState.at
	usable := !at.IsZero() && time.Since(at) >= cpuMinWindow && time.Since(at) <= cpuMaxAge
	if usable {
		cpuState.prev, cpuState.at = now, time.Now()
	}
	cpuState.Unlock()
	if usable {
		if v, ok := cpuPercent(prev, now); ok {
			return v
		}
	}
	first := now
	timer := time.NewTimer(cpuMinWindow)
	select {
	case <-ctx.Done():
		timer.Stop()
		return 0
	case <-timer.C:
	}
	second, ok := readCPUSample()
	if !ok {
		return 0
	}
	cpuState.Lock()
	cpuState.prev, cpuState.at = second, time.Now()
	cpuState.Unlock()
	v, _ := cpuPercent(first, second)
	return v
}

// cpuPercent is the busy share between two readings.
func cpuPercent(a, b cpuSample) (float64, bool) {
	if b.total <= a.total || b.idle < a.idle {
		return 0, false
	}
	total := float64(b.total - a.total)
	idle := float64(b.idle - a.idle)
	return max(0, min(100, (1-idle/total)*100)), true
}

type cpuSample struct {
	total uint64
	idle  uint64
}

func readCPUSample() (cpuSample, bool) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, false
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	return parseCPULine(line)
}

func parseCPULine(line string) (cpuSample, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, false
	}
	var nums []uint64
	for _, field := range fields[1:] {
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuSample{}, false
		}
		nums = append(nums, n)
	}
	var sample cpuSample
	// user nice system idle iowait irq softirq steal; guest time is already
	// part of user and is not counted twice.
	for i, n := range nums {
		if i < 8 {
			sample.total += n
		}
	}
	sample.idle = nums[3]
	if len(nums) > 4 {
		sample.idle += nums[4]
	}
	return sample, true
}

func parseDF(out string) (used, total uint64, ok bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return 0, 0, false
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return 0, 0, false
	}
	total, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || total == 0 {
		return 0, 0, false
	}
	used, err = strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return used, total, true
}

func parseOSRelease(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || key != "PRETTY_NAME" {
			continue
		}
		return strings.Trim(strings.TrimSpace(val), `"'`)
	}
	return ""
}
