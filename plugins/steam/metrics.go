package steam

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
)

func init() {
	metrics.RegisterSource("steam", gameSource)
	metrics.RegisterCheck("steam", gameCheck)
	metrics.RegisterPorts("steam", gamePorts)
}

// gamePorts lets the monitor count the traffic of each game's UDP ports.
func gamePorts(ctx context.Context) []metrics.Port {
	var out []metrics.Port
	for _, g := range sortedGames() {
		if g.ready() {
			out = append(out, metrics.Port{Name: "game-" + g.ID, Label: g.Name, Proto: "udp", Ports: g.currentPorts()})
		}
	}
	return out
}

var actionText = map[string]string{"start": "gestartet", "stop": "gestoppt", "restart": "neu gestartet"}

var jobText = map[string]string{"install": "Installation", "update": "Update", "backup": "Savegame-Backup", "restore": "Wiederherstellung"}

// emitGame records an event of a game, with the acting user if known.
func emitGame(g *Game, level metrics.Status, text, user string) {
	msg := g.Name + ": " + text
	if user != "" {
		msg += " (" + user + ")"
	}
	metrics.Emit(metrics.Event{Source: "steam:" + g.ID, Level: level, Text: msg})
}

// jobEvent marks the start and the end of an install or update, so more
// traffic during the download has its explanation in the charts.
func jobEvent(game, action string, started time.Time, err error, done bool) {
	g, ok := lookup(game)
	if !ok {
		return
	}
	name := jobText[action]
	if name == "" {
		name = action
	}
	switch {
	case !done:
		emitGame(g, metrics.StatusInfo, name+" gestartet", "")
	case err != nil:
		emitGame(g, metrics.StatusWarning, name+" fehlgeschlagen: "+err.Error(), "")
	default:
		emitGame(g, metrics.StatusInfo, fmt.Sprintf("%s abgeschlossen (%s)", name, time.Since(started).Round(time.Second)), "")
	}
}

var (
	infoMu   sync.Mutex
	lastInfo = map[string]ServerInfo{}
)

func gameSource(ctx context.Context) []metrics.Sample {
	var out []metrics.Sample
	for _, g := range sortedGames() {
		if !g.ready() {
			continue
		}
		up := 0.0
		if serviceState(ctx, g) == "active" {
			up = 1
		}
		out = append(out, metrics.Sample{Series: "game:" + g.ID + ":up", Value: up, Label: g.Name + " läuft"})
		if up == 0 || g.QueryPort == nil {
			infoMu.Lock()
			delete(lastInfo, g.ID)
			infoMu.Unlock()
			continue
		}
		port := g.QueryPort(g.currentConfig())
		info, err := QueryInfo(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		infoMu.Lock()
		lastInfo[g.ID] = info
		infoMu.Unlock()
		out = append(out,
			metrics.Sample{Series: "game:" + g.ID + ":players", Value: float64(info.Players), Label: g.Name + " Spieler"},
			metrics.Sample{Series: "game:" + g.ID + ":slots", Value: float64(info.MaxPlayers), Label: g.Name + " Plätze"},
		)
	}
	return out
}

// gameCheck warns when an enabled game server is not running (a failed
// unit is already reported by the units check).
func gameCheck(ctx context.Context) []metrics.Finding {
	var out []metrics.Finding
	for _, g := range sortedGames() {
		if !g.ready() {
			continue
		}
		if jobs.snapshot(g.ID) != nil && jobs.snapshot(g.ID).Running {
			continue
		}
		enabled := strings.TrimSpace(core.RunQuiet(ctx, "systemctl", "is-enabled", g.unit()).Stdout)
		state := serviceState(ctx, g)
		if enabled == "enabled" && state != "active" && state != "activating" && state != "failed" {
			out = append(out, metrics.Finding{ID: "game:" + g.ID, Status: metrics.StatusWarning, Title: "Spielserver läuft nicht: " + g.Name, Detail: "Zustand " + state + ", der Dienst ist aber aktiviert."})
		}
	}
	return out
}
