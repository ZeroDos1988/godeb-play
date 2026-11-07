package apt

import (
	"context"
	"fmt"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
)

func init() {
	metrics.RegisterCheck("updates", updatesCheck)
}

var (
	updatesMu   sync.Mutex
	updatesAt   time.Time
	updatesLast []metrics.Finding
)

// updatesInterval is how often apt list --upgradable is re-read (apt is slow).
const updatesInterval = 30 * time.Minute

// updatesCheck reports pending security updates when automatic installs are
// off, failed automatic godeb-play-apt runs, and (as info) other pending updates.
// Reboot-required stays in backend/metrics (rebootCheck).
func updatesCheck(ctx context.Context) []metrics.Finding {
	updatesMu.Lock()
	defer updatesMu.Unlock()
	if !updatesAt.IsZero() && time.Since(updatesAt) < updatesInterval {
		return updatesLast
	}
	out, env := core.ReadCommand(ctx, "", "apt", "list", "--upgradable")
	if env.Mocked {
		updatesAt = time.Now()
		updatesLast = nil
		return nil
	}
	settings, _ := loadSettings()
	st, hasStatus := readStatus()
	updatesLast = UpdateFindings(ParseUpgradable(out), settings, st, hasStatus)
	updatesAt = time.Now()
	return updatesLast
}

// UpdateFindings turns apt list output, settings and the last godeb-play-apt
// status into monitor findings. Pure helper for tests; same rules as
// godeb-play doctor for counting security packages (-security suite).
func UpdateFindings(pkgs []Package, settings Settings, last Status, hasLast bool) []metrics.Finding {
	var out []metrics.Finding
	total, security := 0, 0
	for _, p := range pkgs {
		total++
		if p.Security {
			security++
		}
	}
	autoSecurity := settings.AutoCheck && settings.AutoSecurity
	switch {
	case security > 0 && !autoSecurity:
		detail := fmt.Sprintf("%d Updates insgesamt. Automatische Sicherheitsupdates sind aus – unter APT einschalten oder manuell einspielen.", total)
		out = append(out, metrics.Finding{
			ID:     "updates",
			Status: metrics.StatusWarning,
			Title:  fmt.Sprintf("%d Sicherheitsupdates offen", security),
			Detail: detail,
		})
	case security > 0:
		out = append(out, metrics.Finding{
			ID:     "updates",
			Status: metrics.StatusInfo,
			Title:  fmt.Sprintf("%d Sicherheitsupdates ausstehend", security),
			Detail: "Die Automatik spielt sie beim nächsten Lauf ein.",
		})
	case total > 0:
		out = append(out, metrics.Finding{
			ID:     "updates",
			Status: metrics.StatusInfo,
			Title:  fmt.Sprintf("%d Updates verfügbar", total),
		})
	}
	if hasLast && last.Trigger == "auto" && last.Finished != "" && !last.OK {
		detail := last.Error
		if detail == "" {
			detail = "ohne Fehlermeldung"
		}
		if last.Action != "" {
			detail = last.Action + ": " + detail
		}
		out = append(out, metrics.Finding{
			ID:     "apt:auto",
			Status: metrics.StatusWarning,
			Title:  "Automatischer APT-Lauf fehlgeschlagen",
			Detail: detail,
		})
	}
	return out
}
