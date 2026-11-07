// Package metrics is GoDeb's monitoring core: plugins register sources
// (numbers sampled every few seconds) and checks (findings for the health
// light), the collector stores a downsampled history and records events
// such as a game update, so a traffic spike has an explanation next to it.
//
// The collector runs in the root agent (plugin monitor). Nothing here
// changes the system; checks only read.
package metrics

import (
	"context"
	"sort"
	"sync"

	"godebplay/backend/core"
)

// Sample is one value of a series. Counter values grow monotonically (bytes
// sent); the collector stores their rate per second instead.
type Sample struct {
	Series  string
	Value   float64
	Counter bool
	Unit    string // "%", "B/s", "B", "" (count), "s"
	Label   string // human readable, German
}

// Source returns the current samples. It must be quick and read-only.
type Source func(ctx context.Context) []Sample

// Status of a finding and of the host overall.
type Status string

const (
	StatusOK       Status = "ok"
	StatusInfo     Status = "info"
	StatusWarning  Status = "warning"
	StatusCritical Status = "critical"
)

func (s Status) rank() int {
	switch s {
	case StatusCritical:
		return 3
	case StatusWarning:
		return 2
	case StatusInfo:
		return 1
	}
	return 0
}

// Worse reports whether a is more severe than b.
func Worse(a, b Status) bool { return a.rank() > b.rank() }

// Finding is one result of a check. ID stays the same while the condition
// lasts, so the collector can tell new problems from old ones.
type Finding struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	// Fix, when set, resolves the finding with one click on the overview.
	Fix *core.Fix `json:"fix,omitempty"`
}

// Check returns findings; an empty result means all is well.
type Check func(ctx context.Context) []Finding

// Event marks something that happened, shown on the time axis.
type Event struct {
	Time   int64  `json:"time"` // unix seconds
	Source string `json:"source"`
	Level  Status `json:"level"`
	Text   string `json:"text"`
}

var (
	regMu   sync.Mutex
	sources = map[string]Source{}
	checks  = map[string]Check{}
	sink    func(Event)
)

// RegisterSource adds a named source. Plugins call it from init().
func RegisterSource(name string, s Source) {
	regMu.Lock()
	defer regMu.Unlock()
	sources[name] = s
}

// RegisterCheck adds a named check. Plugins call it from init().
func RegisterCheck(name string, c Check) {
	regMu.Lock()
	defer regMu.Unlock()
	checks[name] = c
}

// Emit records an event if a collector is running in this process.
func Emit(e Event) {
	regMu.Lock()
	s := sink
	regMu.Unlock()
	if s != nil {
		s(e)
	}
}

func setSink(s func(Event)) {
	regMu.Lock()
	defer regMu.Unlock()
	sink = s
}

type named[T any] struct {
	name string
	fn   T
}

func sorted[T any](m map[string]T) []named[T] {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]named[T], 0, len(m))
	for k, v := range m {
		out = append(out, named[T]{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// Port is a service whose traffic the monitor counts in its own nftables
// table (counters only, no verdicts). Forward counts traffic the host
// forwards (portforward on the hub) instead of local traffic.
type Port struct {
	Name    string // series part: svc:<name>:in / :out
	Label   string
	Proto   string // tcp or udp
	Ports   []int
	Forward bool
}

// PortSource lists ports to count; called every few minutes.
type PortSource func(ctx context.Context) []Port

// Namer maps addresses to names (WireGuard peers) for the connection list.
type Namer func() map[string]string

var (
	portSources = map[string]PortSource{}
	namers      = map[string]Namer{}
)

// RegisterPorts adds a named port source.
func RegisterPorts(name string, p PortSource) {
	regMu.Lock()
	defer regMu.Unlock()
	portSources[name] = p
}

// RegisterNamer adds a named address namer.
func RegisterNamer(name string, n Namer) {
	regMu.Lock()
	defer regMu.Unlock()
	namers[name] = n
}

// Ports collects the ports of all sources, sorted by name.
func Ports(ctx context.Context) []Port {
	var out []Port
	for _, s := range sorted(portSources) {
		out = append(out, s.fn(ctx)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AddressNames merges all namers.
func AddressNames() map[string]string {
	out := map[string]string{}
	for _, n := range sorted(namers) {
		for k, v := range n.fn() {
			out[k] = v
		}
	}
	return out
}
