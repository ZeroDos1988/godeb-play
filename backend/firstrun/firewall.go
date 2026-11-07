package firstrun

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"godebplay/backend/core"
)

// FirewallPlan describes the ufw rules of a set-up GoDeb host.
type FirewallPlan struct {
	SSHPorts   []int
	WireGuard  int    // UDP port to open, 0 for peers and hosts without a hub
	UIPort     int    // GoDeb UI inside the tunnel (wg0)
	LANIface   string // LAN HTTPS access, empty when off
	LANAddress string
	LANPrefix  string
	LANPort    int
	SetupPort  int  // temporary setup rule to remove again
	Enable     bool // switch ufw on with default deny incoming
}

// Rules are the `ufw` argument lists of the plan, SSH first: once ufw is
// enabled, a missing SSH rule locks the admin out of a remote server.
func (p FirewallPlan) Rules() [][]string {
	var rules [][]string
	for _, port := range p.SSHPorts {
		rules = append(rules, []string{"allow", strconv.Itoa(port) + "/tcp", "comment", "SSH"})
	}
	if p.WireGuard > 0 {
		rules = append(rules, []string{"allow", strconv.Itoa(p.WireGuard) + "/udp", "comment", "GoDeb WireGuard"})
	}
	if p.UIPort > 0 {
		rules = append(rules, []string{"allow", "in", "on", "wg0", "to", "any", "port", strconv.Itoa(p.UIPort), "proto", "tcp", "comment", "GoDeb UI im Tunnel"})
	}
	if p.LANIface != "" {
		rules = append(rules, []string{"allow", "in", "on", p.LANIface, "from", p.LANPrefix, "to", p.LANAddress, "port", strconv.Itoa(p.LANPort), "proto", "tcp", "comment", "GoDeb UI im Heimnetz"})
	}
	return rules
}

// ApplyFirewall adds the rules and, if requested, enables ufw. ufw is only
// switched on when at least one SSH rule was added. It returns log lines.
func ApplyFirewall(ctx context.Context, p FirewallPlan) ([]string, error) {
	var log []string
	status := core.RunAdmin(ctx, "ufw", "status")
	if status.Err != nil {
		return []string{"ufw nicht verfügbar (" + status.Detail() + "), Firewall bitte selbst einrichten."}, nil
	}
	sshOK := len(p.SSHPorts) > 0
	for i, rule := range p.Rules() {
		res := core.RunAdmin(ctx, "ufw", rule...)
		if res.Err != nil {
			log = append(log, fmt.Sprintf("ufw %s: %s", strings.Join(rule, " "), res.Detail()))
			if i < len(p.SSHPorts) {
				sshOK = false
			}
			continue
		}
		log = append(log, "ufw "+strings.Join(rule[:len(rule)-2], " "))
	}
	if p.SetupPort > 0 {
		core.RunAdmin(ctx, "ufw", "--force", "delete", "allow", strconv.Itoa(p.SetupPort)+"/tcp")
	}
	if strings.Contains(status.Stdout, "Status: active") {
		return append(log, "ufw ist aktiv."), nil
	}
	if !p.Enable {
		return append(log, "ufw bleibt aus."), nil
	}
	if !sshOK {
		return append(log, "SSH-Port nicht erkannt oder nicht freigegeben, ufw bleibt deshalb aus."), nil
	}
	for _, args := range [][]string{{"default", "deny", "incoming"}, {"default", "allow", "outgoing"}, {"--force", "enable"}} {
		if res := core.RunAdmin(ctx, "ufw", args...); res.Err != nil {
			return log, fmt.Errorf("ufw %s: %s", strings.Join(args, " "), res.Detail())
		}
	}
	return append(log, "ufw ist aktiv (eingehend: deny, ausgehend: allow)."), nil
}
