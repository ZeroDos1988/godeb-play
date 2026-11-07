package monitor

import (
	"bufio"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
)

func init() {
	extraRoutes = append(extraRoutes, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/plugins/monitor/connections", handleConnections)
	})
}

var conntrackPath = "/proc/net/nf_conntrack"

// Connection is one tracked flow, from the view of this host.
type Connection struct {
	Proto     string `json:"proto"`
	Direction string `json:"direction"` // in, out, forward
	Remote    string `json:"remote"`
	Local     string `json:"local"`
	Port      int    `json:"port"` // service port (destination of the first packet)
	Service   string `json:"service,omitempty"`
	Name      string `json:"name,omitempty"` // WireGuard peer of the remote address
	State     string `json:"state,omitempty"`
	Bytes     uint64 `json:"bytes"`
	Packets   uint64 `json:"packets"`
}

// RemoteSummary groups connections by remote address.
type RemoteSummary struct {
	Remote      string   `json:"remote"`
	Name        string   `json:"name,omitempty"`
	Connections int      `json:"connections"`
	Bytes       uint64   `json:"bytes"`
	Services    []string `json:"services"`
}

type connectionsResponse struct {
	core.CommandEnvelope
	Total       int             `json:"total"`
	Accounting  bool            `json:"accounting"` // conntrack counts bytes
	Connections []Connection    `json:"connections"`
	Remotes     []RemoteSummary `json:"remotes"`
}

type flowSide struct {
	src, dst     string
	sport, dport int
	bytes, pkts  uint64
}

// ParseConntrack reads /proc/net/nf_conntrack lines. Both directions of a
// flow are on one line: the first src=/dst= group is the original
// direction, the second the reply.
func ParseConntrack(data string, local func(string) bool) ([]Connection, bool) {
	var out []Connection
	accounting := false
	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Buffer(make([]byte, 16<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		proto := f[2]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		state := ""
		if proto == "tcp" && len(f) > 5 && !strings.Contains(f[5], "=") {
			state = f[5]
		}
		var sides []flowSide
		cur := -1
		for _, kv := range f {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			if k == "src" {
				sides = append(sides, flowSide{})
				cur = len(sides) - 1
			}
			if cur < 0 || cur > 1 {
				continue
			}
			s := &sides[cur]
			switch k {
			case "src":
				s.src = v
			case "dst":
				s.dst = v
			case "sport":
				s.sport, _ = strconv.Atoi(v)
			case "dport":
				s.dport, _ = strconv.Atoi(v)
			case "bytes":
				s.bytes, _ = strconv.ParseUint(v, 10, 64)
				accounting = true
			case "packets":
				s.pkts, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		if len(sides) < 2 {
			continue
		}
		o, r := sides[0], sides[1]
		c := Connection{Proto: proto, State: state, Port: o.dport, Bytes: o.bytes + r.bytes, Packets: o.pkts + r.pkts}
		switch {
		case r.src != o.dst && !local(r.src):
			// DNAT (port forwarding): the reply comes from the real target.
			c.Direction, c.Remote, c.Local = "forward", o.src, r.src
		case local(o.dst) && !local(o.src):
			c.Direction, c.Remote, c.Local = "in", o.src, o.dst
		case local(o.src) && !local(o.dst):
			c.Direction, c.Remote, c.Local = "out", o.dst, o.src
		case local(o.src) && local(o.dst):
			continue // loopback and host-internal traffic
		default:
			c.Direction, c.Remote, c.Local = "forward", o.src, o.dst
		}
		out = append(out, c)
	}
	return out, accounting
}

func localAddrs() func(string) bool {
	set := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				set[p.Addr().Unmap().String()] = true
			}
		}
	}
	return func(ip string) bool {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return false
		}
		a = a.Unmap()
		return set[a.String()] || a.IsLoopback()
	}
}

// serviceNames maps proto/port to the accounting labels.
func serviceNames() map[string]string {
	m := map[string]string{}
	for _, p := range AcctPorts() {
		for _, n := range p.Ports {
			m[p.Proto+"/"+strconv.Itoa(n)] = p.Label
		}
	}
	return m
}

const maxConnections = 200

func handleConnections(w http.ResponseWriter, r *http.Request) {
	resp := connectionsResponse{Connections: []Connection{}, Remotes: []RemoteSummary{}}
	resp.Command = []string{"cat", conntrackPath}
	raw, err := os.ReadFile(conntrackPath)
	var conns []Connection
	if err != nil {
		resp.Mocked = true
		resp.Detail = err.Error()
		conns, resp.Accounting = ParseConntrack(sampleConntrack, func(ip string) bool { return ip == "203.0.113.1" || ip == "10.8.0.1" })
	} else {
		conns, resp.Accounting = ParseConntrack(string(raw), localAddrs())
	}
	names := metrics.AddressNames()
	services := serviceNames()
	groups := map[string]*RemoteSummary{}
	for i := range conns {
		c := &conns[i]
		c.Service = services[c.Proto+"/"+strconv.Itoa(c.Port)]
		c.Name = names[c.Remote]
		g := groups[c.Remote]
		if g == nil {
			g = &RemoteSummary{Remote: c.Remote, Name: c.Name}
			groups[c.Remote] = g
		}
		g.Connections++
		g.Bytes += c.Bytes
		label := c.Service
		if label == "" {
			label = c.Proto + "/" + strconv.Itoa(c.Port)
		}
		if !containsString(g.Services, label) && len(g.Services) < 6 {
			g.Services = append(g.Services, label)
		}
	}
	resp.Total = len(conns)
	sort.SliceStable(conns, func(i, j int) bool {
		if conns[i].Bytes != conns[j].Bytes {
			return conns[i].Bytes > conns[j].Bytes
		}
		return conns[i].Remote < conns[j].Remote
	})
	if len(conns) > maxConnections {
		conns = conns[:maxConnections]
	}
	resp.Connections = conns
	for _, g := range groups {
		resp.Remotes = append(resp.Remotes, *g)
	}
	sort.Slice(resp.Remotes, func(i, j int) bool {
		a, b := resp.Remotes[i], resp.Remotes[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		if a.Connections != b.Connections {
			return a.Connections > b.Connections
		}
		return a.Remote < b.Remote
	})
	if len(resp.Remotes) > 50 {
		resp.Remotes = resp.Remotes[:50]
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

const sampleConntrack = `ipv4     2 udp      17 170 src=198.51.100.23 dst=203.0.113.1 sport=50211 dport=15637 src=10.8.0.2 dst=10.8.0.1 sport=15637 dport=50211 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.44 dst=203.0.113.1 sport=51514 dport=22 src=203.0.113.1 dst=192.0.2.44 sport=22 dport=51514 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 179 src=10.8.0.2 dst=203.0.113.1 sport=51820 dport=51820 src=203.0.113.1 dst=10.8.0.2 sport=51820 dport=51820 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 299 ESTABLISHED src=10.8.0.5 dst=10.8.0.1 sport=40112 dport=8080 src=10.8.0.1 dst=10.8.0.5 sport=8080 dport=40112 [ASSURED] mark=0 zone=0 use=2
`
