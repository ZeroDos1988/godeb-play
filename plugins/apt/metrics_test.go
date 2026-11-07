package apt

import (
	"strings"
	"testing"

	"godebplay/backend/metrics"
)

const sampleList = `Listing...
openssl/trixie-security 3.5.4-1~deb13u2 amd64 [upgradable from: 3.5.4-1~deb13u1]
libssl3t64/trixie-security,trixie-updates 3.5.4-1~deb13u2 amd64 [upgradable from: 3.5.4-1~deb13u1]
bash/trixie 5.2.37-2+b5 amd64 [upgradable from: 5.2.37-2]
`

func TestUpdateFindingsSecurityWhenAutoOff(t *testing.T) {
	pkgs := ParseUpgradable(sampleList)
	got := UpdateFindings(pkgs, Settings{AutoCheck: true, Interval: 10, AutoSecurity: false}, Status{}, false)
	if len(got) != 1 || got[0].ID != "updates" || got[0].Status != metrics.StatusWarning {
		t.Fatalf("auto off: %+v", got)
	}
	if !strings.Contains(got[0].Title, "2 Sicherheitsupdates") {
		t.Fatalf("title = %q", got[0].Title)
	}

	got = UpdateFindings(pkgs, Settings{AutoCheck: false, Interval: 10, AutoSecurity: true}, Status{}, false)
	if len(got) != 1 || got[0].Status != metrics.StatusWarning {
		t.Fatalf("check off: %+v", got)
	}

	got = UpdateFindings(pkgs, Settings{AutoCheck: true, Interval: 10, AutoSecurity: true}, Status{}, false)
	if len(got) != 1 || got[0].Status != metrics.StatusInfo || !strings.Contains(got[0].Title, "ausstehend") {
		t.Fatalf("auto on: %+v", got)
	}
}

func TestUpdateFindingsOrdinaryAndFailedAuto(t *testing.T) {
	pkgs := ParseUpgradable("bash/trixie 5.2.37-2 amd64 [upgradable from: 5.2.37-1]\n")
	got := UpdateFindings(pkgs, defaultSettings(), Status{}, false)
	if len(got) != 1 || got[0].Status != metrics.StatusInfo || !strings.Contains(got[0].Title, "1 Updates") {
		t.Fatalf("ordinary: %+v", got)
	}

	failed := Status{Action: ActionSecurity, Trigger: "auto", Finished: "2026-10-27T12:00:00Z", OK: false, Error: "exit status 1"}
	got = UpdateFindings(nil, defaultSettings(), failed, true)
	if len(got) != 1 || got[0].ID != "apt:auto" || got[0].Status != metrics.StatusWarning {
		t.Fatalf("failed auto: %+v", got)
	}
	if !strings.Contains(got[0].Detail, ActionSecurity) || !strings.Contains(got[0].Detail, "exit status 1") {
		t.Fatalf("detail = %q", got[0].Detail)
	}

	// Manual failures and still-running jobs do not warn.
	manual := failed
	manual.Trigger = "admin"
	if got := UpdateFindings(nil, defaultSettings(), manual, true); len(got) != 0 {
		t.Fatalf("manual failure: %+v", got)
	}
	running := Status{Action: ActionCheck, Trigger: "auto", OK: false}
	if got := UpdateFindings(nil, defaultSettings(), running, true); len(got) != 0 {
		t.Fatalf("running: %+v", got)
	}
	ok := Status{Action: ActionSecurity, Trigger: "auto", Finished: "2026-10-27T12:00:00Z", OK: true}
	if got := UpdateFindings(nil, defaultSettings(), ok, true); len(got) != 0 {
		t.Fatalf("ok auto: %+v", got)
	}
}

func TestUpdateFindingsCombines(t *testing.T) {
	pkgs := ParseUpgradable(sampleList)
	failed := Status{Action: ActionCheck, Trigger: "auto", Finished: "2026-10-27T12:00:00Z", OK: false, Error: "Netzwerk"}
	got := UpdateFindings(pkgs, Settings{AutoCheck: false, Interval: 10}, failed, true)
	if len(got) != 2 {
		t.Fatalf("got %d findings: %+v", len(got), got)
	}
}
