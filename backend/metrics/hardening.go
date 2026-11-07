package metrics

import (
	"context"
	"strings"

	"godebplay/backend/core"
)

func init() {
	RegisterCheck("hardening", hardeningCheck)
}

// hardeningCheck reports SSH password login and whether unattended-upgrades
// is enabled. It only observes; GoDeb's APT plugin handles security updates.
func hardeningCheck(ctx context.Context) []Finding {
	var out []Finding
	sshd, env := core.ReadCommand(ctx, "", "sshd", "-T")
	if !env.Mocked && sshd != "" {
		pass, root := "", ""
		for _, l := range strings.Split(sshd, "\n") {
			f := strings.Fields(strings.ToLower(l))
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "passwordauthentication":
				pass = f[1]
			case "permitrootlogin":
				root = f[1]
			}
		}
		if pass == "yes" {
			out = append(out, Finding{ID: "ssh:password", Status: StatusWarning, Title: "SSH erlaubt Passwort-Login", Detail: "PasswordAuthentication yes"})
		}
		if root == "yes" {
			out = append(out, Finding{ID: "ssh:root", Status: StatusWarning, Title: "Root-SSH mit Passwort erlaubt", Detail: "PermitRootLogin yes"})
		}
	}
	uu, env := core.ReadCommand(ctx, "", "systemctl", "is-enabled", "unattended-upgrades.service")
	if !env.Mocked {
		state := strings.TrimSpace(uu)
		if state != "" && state != "enabled" {
			out = append(out, Finding{
				ID:     "apt:unattended",
				Status: StatusInfo,
				Title:  "unattended-upgrades: " + state,
				Detail: "GoDeb spielt Sicherheitsupdates über das APT-Plugin ein; unattended-upgrades ist optional",
			})
		}
	}
	return out
}
