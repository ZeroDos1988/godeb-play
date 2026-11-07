package monitor

import (
	"strings"
	"testing"
	"time"

	"godebplay/backend/metrics"
	"godebplay/plugins/logs"
)

func TestCleanPortsAndRender(t *testing.T) {
	ports := cleanPorts([]metrics.Port{
		{Name: "ssh", Proto: "tcp", Ports: []int{22, 22, 2222}},
		{Name: "game-enshrouded", Proto: "udp", Ports: []int{15637, 15636}},
		{Name: "fwd-ens", Proto: "udp", Ports: []int{15636}, Forward: true},
		{Name: "bad name", Proto: "tcp", Ports: []int{1}},
		{Name: "icmp", Proto: "icmp", Ports: []int{1}},
		{Name: "zero", Proto: "tcp", Ports: []int{0, 70000}},
		{Name: "ssh", Proto: "tcp", Ports: []int{23}},
	})
	if len(ports) != 3 {
		t.Fatalf("ports = %+v", ports)
	}
	script := RenderAcct(ports)
	for _, want := range []string{
		"table inet godeb_acct {}\ndelete table inet godeb_acct\n",
		"counter game_enshrouded_in {}",
		"type filter hook input priority 10; policy accept;",
		"meta l4proto tcp th dport { 22, 2222 } counter name ssh_in",
		"meta l4proto udp th sport { 15636, 15637 } counter name game_enshrouded_out",
		"meta l4proto udp th dport { 15636 } counter name fwd_ens_in",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in\n%s", want, script)
		}
	}
	for _, verdict := range []string{"drop", "reject", "accept\n", "jump", "goto"} {
		if strings.Contains(strings.ReplaceAll(script, "policy accept;", ""), verdict) {
			t.Fatalf("accounting table must not contain %q", verdict)
		}
	}
	// Forwarded ports are only counted in the forward chain.
	input := script[strings.Index(script, "chain input"):strings.Index(script, "chain output")]
	if strings.Contains(input, "fwd_ens") {
		t.Fatal("forward rule in input chain")
	}
}

func TestParseCounters(t *testing.T) {
	out := `{"nftables": [{"metainfo": {"version": "1.1.3"}}, {"counter": {"family": "inet", "name": "ssh_in", "table": "godeb_acct", "handle": 1, "packets": 10, "bytes": 1234}}, {"counter": {"family": "inet", "name": "x", "table": "other", "bytes": 5}}]}`
	m := ParseCounters(out)
	if len(m) != 1 || m["ssh_in"] != 1234 {
		t.Fatalf("counters = %v", m)
	}
	if ParseCounters("kaputt") != nil {
		t.Fatal("invalid JSON must give nil")
	}
}

func TestParseConntrack(t *testing.T) {
	local := func(ip string) bool { return ip == "203.0.113.1" || ip == "10.8.0.1" }
	conns, acct := ParseConntrack(sampleConntrack+"ipv4 2 icmp 1 29 src=1.1.1.1 dst=203.0.113.1 type=8 code=0 id=1 src=203.0.113.1 dst=1.1.1.1 type=0 code=0 id=1 mark=0 use=1\nkaputt\n", local)
	if acct || len(conns) != 4 {
		t.Fatalf("conns = %+v acct=%v", conns, acct)
	}
	game := conns[0]
	if game.Direction != "forward" || game.Remote != "198.51.100.23" || game.Local != "10.8.0.2" || game.Port != 15637 {
		t.Fatalf("forwarded game = %+v", game)
	}
	ssh := conns[1]
	if ssh.Direction != "in" || ssh.Remote != "192.0.2.44" || ssh.Port != 22 || ssh.State != "ESTABLISHED" {
		t.Fatalf("ssh = %+v", ssh)
	}
	withBytes, acct := ParseConntrack("ipv4 2 tcp 6 10 ESTABLISHED src=192.0.2.1 dst=203.0.113.1 sport=1 dport=443 packets=3 bytes=300 src=203.0.113.1 dst=192.0.2.1 sport=443 dport=1 packets=2 bytes=1000 [ASSURED] use=1\n", local)
	if !acct || withBytes[0].Bytes != 1300 || withBytes[0].Packets != 5 {
		t.Fatalf("accounting = %+v", withBytes)
	}
}

func TestAccessParsers(t *testing.T) {
	ssh := ParseSSH([]logs.Entry{
		{Time: 1000_000, Message: "Accepted publickey for root from 192.0.2.44 port 51514 ssh2: ED25519 SHA256:abc"},
		{Time: 2000_000, Message: "Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2"},
		{Time: 2001_000, Message: "Invalid user admin from 198.51.100.7 port 40022"},
		{Time: 3000_000, Message: "Failed publickey for root from ::ffff:198.51.100.8 port 1 ssh2"},
		{Time: 4000_000, Message: "Connection closed by 1.2.3.4 port 5"},
	})
	if len(ssh) != 3 || !ssh[0].OK || ssh[0].User != "root" || ssh[0].Time != 1000 {
		t.Fatalf("ssh = %+v", ssh)
	}
	if ssh[1].User != "admin" || ssh[1].OK || ssh[2].IP != "198.51.100.8" {
		t.Fatalf("failures = %+v", ssh[1:])
	}

	godeb := ParseGoDeb(logs.ParseJournal(`{"__REALTIME_TIMESTAMP":"5000000000","_SYSTEMD_UNIT":"godeb-play.service","MESSAGE":"level=INFO msg=\"Anmeldung erfolgreich\" komponente=web benutzer=admin ip=10.8.0.5"}
{"__REALTIME_TIMESTAMP":"6000000000","_SYSTEMD_UNIT":"godeb-play-agent.service","MESSAGE":"level=INFO msg=Aktion komponente=agent methode=POST pfad=/api/plugins/wireguard/peers status=200 benutzer=admin ip=10.8.0.5"}
{"__REALTIME_TIMESTAMP":"7000000000","_SYSTEMD_UNIT":"godeb-play.service","MESSAGE":"level=INFO msg=\"GoDeb lauscht\" komponente=web"}
`))
	if len(godeb) != 2 || godeb[0].Kind != "login" || !godeb[0].OK || godeb[1].Kind != "action" || godeb[1].Detail != "POST /api/plugins/wireguard/peers 200" {
		t.Fatalf("godeb = %+v", godeb)
	}

	since := time.Date(2026, 10, 23, 0, 0, 0, 0, time.Local)
	bans := ParseFail2banLog(strings.NewReader("2026-10-22 23:00:00,1 fail2ban.actions        [811]: NOTICE  [sshd] Ban 1.1.1.1\n2026-10-23 10:00:00,123 fail2ban.actions        [811]: NOTICE  [sshd] Ban 198.51.100.7\n2026-10-23 10:05:00,1 fail2ban.actions [811]: NOTICE  [sshd] Unban 198.51.100.7\n"), since)
	if len(bans) != 1 || bans[0].IP != "198.51.100.7" || bans[0].Detail != "sshd" {
		t.Fatalf("bans = %+v", bans)
	}

	total, top := ParseUFW([]logs.Entry{
		{Message: "[UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=203.0.113.9 DST=1.2.3.4 LEN=40 PROTO=TCP SPT=1 DPT=23 WINDOW=1"},
		{Message: "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=1.2.3.4 PROTO=TCP SPT=1 DPT=3389"},
		{Message: "[UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.1 DST=1.2.3.4 PROTO=UDP SPT=1 DPT=53"},
		{Message: "[UFW AUDIT] SRC=192.0.2.1"},
	})
	if total != 3 || top[0].IP != "203.0.113.9" || top[0].Count != 2 || len(top[0].Ports) != 2 || top[0].Ports[0] != "tcp/23" {
		t.Fatalf("ufw = %d %+v", total, top)
	}
}
