package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
)

// The monitor counts traffic per service in its own nftables table. It
// holds named counters and accept-policy chains without any verdict, so it
// can never block or let through anything; it runs after the filter
// (priority 10), so dropped packets are not counted. The table is rebuilt
// from scratch whenever the list of services changes and after a reboot.
const acctTable = "godeb_acct"

const acctRefresh = 5 * time.Minute

func init() {
	metrics.RegisterSource("acct", acctSource)
	metrics.RegisterPorts("base", basePorts)
}

var counterName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// basePorts are services every GoDeb host has.
func basePorts(ctx context.Context) []metrics.Port {
	ssh := core.SSHPorts(ctx)
	if len(ssh) == 0 {
		ssh = []int{22}
	}
	return []metrics.Port{
		{Name: "ssh", Label: "SSH", Proto: "tcp", Ports: ssh},
		{Name: "godeb", Label: "GoDeb Play", Proto: "tcp", Ports: []int{8080, 8443}},
		{Name: "web", Label: "HTTP/HTTPS", Proto: "tcp", Ports: []int{80, 443}},
		{Name: "mail", Label: "Mail", Proto: "tcp", Ports: []int{25, 465, 587}},
	}
}

var (
	acctMu    sync.Mutex
	acctAt    time.Time
	acctHash  string
	acctPorts []metrics.Port
	acctOK    bool
)

// AcctPorts returns the services currently counted.
func AcctPorts() []metrics.Port {
	acctMu.Lock()
	defer acctMu.Unlock()
	return append([]metrics.Port(nil), acctPorts...)
}

// cleanPorts drops invalid entries: names outside the counter alphabet,
// protocols other than tcp/udp, ports outside 1-65535.
func cleanPorts(in []metrics.Port) []metrics.Port {
	var out []metrics.Port
	seen := map[string]bool{}
	for _, p := range in {
		if p.Proto != "tcp" && p.Proto != "udp" {
			continue
		}
		id := strings.ReplaceAll(p.Name, "-", "_")
		if !counterName.MatchString(id) || seen[id] {
			continue
		}
		var ports []int
		for _, n := range p.Ports {
			if n > 0 && n < 65536 && !containsInt(ports, n) {
				ports = append(ports, n)
			}
		}
		if len(ports) == 0 {
			continue
		}
		sort.Ints(ports)
		seen[id] = true
		p.Ports = ports
		out = append(out, p)
	}
	return out
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

// RenderAcct builds the nft script that replaces the table.
func RenderAcct(ports []metrics.Port) string {
	var b strings.Builder
	// Create first so the delete never fails, then rebuild in the same
	// transaction.
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\ntable inet %s {\n", acctTable, acctTable, acctTable)
	for _, p := range ports {
		id := strings.ReplaceAll(p.Name, "-", "_")
		fmt.Fprintf(&b, "\tcounter %s_in {}\n\tcounter %s_out {}\n", id, id)
	}
	chain := func(name, hook string, forward bool) {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority 10; policy accept;\n", name, hook)
		for _, p := range ports {
			if p.Forward != forward {
				continue
			}
			id := strings.ReplaceAll(p.Name, "-", "_")
			set := joinInts(p.Ports)
			switch hook {
			case "input":
				fmt.Fprintf(&b, "\t\tmeta l4proto %s th dport { %s } counter name %s_in\n", p.Proto, set, id)
			case "output":
				fmt.Fprintf(&b, "\t\tmeta l4proto %s th sport { %s } counter name %s_out\n", p.Proto, set, id)
			case "forward":
				fmt.Fprintf(&b, "\t\tmeta l4proto %s th dport { %s } counter name %s_in\n", p.Proto, set, id)
				fmt.Fprintf(&b, "\t\tmeta l4proto %s th sport { %s } counter name %s_out\n", p.Proto, set, id)
			}
		}
		b.WriteString("\t}\n")
	}
	chain("input", "input", false)
	chain("output", "output", false)
	chain("forward", "forward", true)
	b.WriteString("}\n")
	return b.String()
}

func joinInts(list []int) string {
	s := make([]string, len(list))
	for i, n := range list {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

// ensureAcct rebuilds the table when the services changed, the table is
// missing (reboot, nft flush) or every acctRefresh to pick up new ports.
func ensureAcct(ctx context.Context, force bool) {
	acctMu.Lock()
	defer acctMu.Unlock()
	if !force && time.Since(acctAt) < acctRefresh {
		return
	}
	acctAt = time.Now()
	ports := cleanPorts(metrics.Ports(ctx))
	script := RenderAcct(ports)
	sum := sha256.Sum256([]byte(script))
	hash := fmt.Sprintf("%x", sum[:8])
	if hash == acctHash && acctOK && !force {
		return
	}
	res := core.RunAdminInput(ctx, script, "nft", "-f", "-")
	if res.Err != nil {
		if acctOK || acctHash == "" {
			slog.Warn("Traffic-Zähler (nftables) nicht angelegt", "fehler", res.Detail())
		}
		acctOK, acctHash = false, hash
		return
	}
	if hash != acctHash {
		slog.Info("Traffic-Zähler angelegt", "tabelle", "inet "+acctTable, "dienste", len(ports))
	}
	acctOK, acctHash, acctPorts = true, hash, ports
}

type nftCounters struct {
	Nftables []struct {
		Counter *struct {
			Name  string `json:"name"`
			Table string `json:"table"`
			Bytes uint64 `json:"bytes"`
		} `json:"counter"`
	} `json:"nftables"`
}

// ParseCounters reads `nft -j list counters table inet godeb_acct`.
func ParseCounters(out string) map[string]uint64 {
	var c nftCounters
	if json.Unmarshal([]byte(out), &c) != nil {
		return nil
	}
	m := map[string]uint64{}
	for _, e := range c.Nftables {
		if e.Counter != nil && e.Counter.Table == acctTable {
			m[e.Counter.Name] = e.Counter.Bytes
		}
	}
	return m
}

func acctSource(ctx context.Context) []metrics.Sample {
	ensureAcct(ctx, false)
	acctMu.Lock()
	ok, ports := acctOK, acctPorts
	acctMu.Unlock()
	if !ok {
		return nil
	}
	out, env := core.ReadCommand(ctx, "", "nft", "-j", "list", "counters", "table", "inet", acctTable)
	if env.Mocked {
		// Table gone (reboot of nftables, flush): rebuild next time.
		ensureAcct(ctx, true)
		return nil
	}
	counters := ParseCounters(out)
	var samples []metrics.Sample
	for _, p := range ports {
		id := strings.ReplaceAll(p.Name, "-", "_")
		in, okIn := counters[id+"_in"]
		outB, okOut := counters[id+"_out"]
		if !okIn || !okOut {
			continue
		}
		samples = append(samples,
			metrics.Sample{Series: "svc:" + p.Name + ":in", Value: float64(in), Counter: true, Unit: "B/s", Label: p.Label},
			metrics.Sample{Series: "svc:" + p.Name + ":out", Value: float64(outB), Counter: true, Unit: "B/s", Label: p.Label},
		)
	}
	return samples
}
