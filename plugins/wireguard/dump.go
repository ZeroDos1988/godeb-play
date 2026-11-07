package wireguard

import (
	"strconv"
	"strings"
)

// LivePeer is one peer line from `wg show <iface> dump` without the preshared key.
type LivePeer struct {
	PublicKey       string
	Endpoint        string
	AllowedIPs      []string
	LatestHandshake int64
	RxBytes         int64
	TxBytes         int64
}

// LiveInterface is the parsed dump. The private key column is discarded.
type LiveInterface struct {
	PublicKey  string
	ListenPort string
	Peers      []LivePeer
}

const sampleDump = "not-a-real-key\texample-server-public-key\t51820\toff\n" +
	"example-peer-public-key\t(none)\t203.0.113.10:51820\t10.8.0.2/32\t1760380000\t1482734\t20941823\t25\n"

// ParseDump reads the tab-separated output of `wg show <iface> dump`.
func ParseDump(out string) LiveInterface {
	live := LiveInterface{Peers: []LivePeer{}}
	first := true
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if first {
			first = false
			if len(fields) >= 3 {
				live.PublicKey = none(fields[1])
				live.ListenPort = none(fields[2])
			}
			continue
		}
		if len(fields) < 8 {
			continue
		}
		peer := LivePeer{
			PublicKey:  none(fields[0]),
			Endpoint:   none(fields[2]),
			AllowedIPs: []string{},
		}
		if ips := none(fields[3]); ips != "" {
			peer.AllowedIPs = splitList(ips)
		}
		peer.LatestHandshake, _ = strconv.ParseInt(fields[4], 10, 64)
		peer.RxBytes, _ = strconv.ParseInt(fields[5], 10, 64)
		peer.TxBytes, _ = strconv.ParseInt(fields[6], 10, 64)
		live.Peers = append(live.Peers, peer)
	}
	return live
}

func none(v string) string {
	v = strings.TrimSpace(v)
	if v == "(none)" {
		return ""
	}
	return v
}
