// Package steam installs and manages dedicated game servers through SteamCMD.
// Everything that is the same for every game lives here: SteamCMD, the
// install/update job, a service account, a sandboxed systemd unit, the
// firewall, logs and savegame backups. A game only describes itself (Game): app ID, start
// command, ports and its configuration file. Enshrouded is the first game.
package steam

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Platform of the server binary. Windows servers run under Debian's Wine
// or under GE-Proton (proton.go), which many Windows servers need.
const (
	Linux   = "linux"
	Windows = "windows"
	Proton  = "proton"
)

// Game describes one dedicated server. All fields are constants in code;
// nothing here comes from a request.
type Game struct {
	ID       string // URL segment, account and unit suffix: [a-z][a-z0-9]{1,15}
	Name     string
	AppID    string // Steam app ID of the dedicated server
	Platform string // Linux, Windows (Wine) or Proton (GE-Proton)
	// Executable is the server binary relative to the server directory.
	Executable string
	Args       []string
	// Packages are extra APT packages, e.g. wine for Windows servers.
	Packages []string
	// StopSignal ends the server cleanly so it saves first.
	StopSignal string
	// DownloadGB and MemoryGB are shown before installing.
	DownloadGB int
	MemoryGB   int

	// ConfigFile is relative to the server directory; empty means the game
	// has no file GoDeb edits.
	ConfigFile     string
	DefaultConfig  func() ([]byte, error)
	ValidateConfig func(raw []byte) (map[string]any, error)
	// Ports returns the UDP ports to open for a parsed configuration; cfg is
	// nil when no configuration exists yet.
	Ports func(cfg map[string]any) []int
	// QueryPort is the Steam query (A2S) port for player counts; nil when
	// the game does not answer A2S.
	QueryPort func(cfg map[string]any) int
	// TCPPorts are TCP ports to open in addition (nil for UDP-only games).
	TCPPorts func(cfg map[string]any) []int
	// SaveDir returns the savegame directory relative to the game's base
	// directory, e.g. "server/savegame" or ".config/…" below HOME (cfg may
	// be nil); nil when the game has no backups.
	SaveDir func(cfg map[string]any) string
	// LibDirs are directories below the server directory for
	// LD_LIBRARY_PATH (Unity servers ship their own libraries).
	LibDirs []string
	// UnitEnv are fixed environment variables of the unit (KEY=value).
	UnitEnv []string
	// Settings turns a validated configuration into environment variables
	// for the unit. The agent writes them to a root-only file in
	// /etc/godeb-play/games, and Args refer to them as ${NAME}: settings
	// such as a server password never pass through files the game owns.
	Settings func(cfg map[string]any) (map[string]string, error)
}

var (
	games       = map[string]*Game{}
	gameID      = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)
	packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,62}$`)
	// unitEnvPattern: fixed variables in code, nothing that needs quoting.
	unitEnvPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}=[A-Za-z0-9_./:-]{0,200}$`)
)

// register adds a game at init time. Invalid definitions are programming
// errors and stop the daemon early.
func register(g *Game) {
	switch {
	case !gameID.MatchString(g.ID):
		panic("steam: invalid game ID " + g.ID)
	case games[g.ID] != nil:
		panic("steam: duplicate game " + g.ID)
	case g.AppID == "" || strings.Trim(g.AppID, "0123456789") != "":
		panic("steam: invalid app ID for " + g.ID)
	case g.Platform != Linux && g.Platform != Windows && g.Platform != Proton:
		panic("steam: invalid platform for " + g.ID)
	case g.Executable == "" || filepath.IsAbs(g.Executable) || strings.Contains(g.Executable, ".."):
		panic("steam: invalid executable for " + g.ID)
	case g.Ports == nil:
		panic("steam: no ports for " + g.ID)
	case g.ConfigFile != "" && (g.DefaultConfig == nil || g.ValidateConfig == nil):
		panic("steam: config file without default/validation for " + g.ID)
	case g.Settings != nil && g.ConfigFile == "":
		panic("steam: settings without config file for " + g.ID)
	}
	for _, kv := range g.UnitEnv {
		if !unitEnvPattern.MatchString(kv) {
			panic("steam: invalid unit environment " + kv)
		}
	}
	for _, dir := range g.LibDirs {
		if !safeRelative(dir) || strings.ContainsAny(dir, " \"") {
			panic("steam: invalid library dir " + dir)
		}
	}
	for _, a := range g.Args {
		if strings.ContainsAny(a, "\n\"'\\%;") {
			panic("steam: invalid argument " + a)
		}
	}
	for _, p := range g.Packages {
		if !packageName.MatchString(p) {
			panic("steam: invalid package " + p)
		}
	}
	if g.StopSignal == "" {
		g.StopSignal = "SIGINT"
	}
	games[g.ID] = g
}

// lookup returns the game for a path value.
func lookup(id string) (*Game, bool) {
	g, ok := games[id]
	return g, ok
}

// sortedGames lists games by name.
func sortedGames() []*Game {
	out := make([]*Game, 0, len(games))
	for _, g := range games {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// rootDir holds one directory per game. Tests and unprivileged development
// runs point GODEB_STEAM_ROOT elsewhere.
func rootDir() string {
	if dir := strings.TrimSpace(os.Getenv("GODEB_STEAM_ROOT")); dir != "" {
		return filepath.Clean(dir)
	}
	return "/var/lib/godeb-play-games"
}

// Per game: SteamCMD, server files and Wine prefix sit below baseDir, which
// is also the only path the server's unit may write to.
func (g *Game) baseDir() string     { return filepath.Join(rootDir(), g.ID) }
func (g *Game) serverDir() string   { return filepath.Join(g.baseDir(), "server") }
func (g *Game) steamcmdDir() string { return filepath.Join(g.baseDir(), "steamcmd") }
func (g *Game) winePrefix() string  { return filepath.Join(g.baseDir(), "wine") }
func (g *Game) executable() string  { return filepath.Join(g.serverDir(), g.Executable) }

// windowsBinary reports whether SteamCMD must fetch the Windows build.
func (g *Game) windowsBinary() bool { return g.Platform == Windows || g.Platform == Proton }

// user is the game's own service account, so one compromised server cannot
// touch another game's files.
func (g *Game) user() string { return "steam-" + g.ID }
func (g *Game) unit() string { return "godeb-play-" + g.ID + ".service" }

func (g *Game) configPath() string {
	if g.ConfigFile == "" {
		return ""
	}
	return filepath.Join(g.serverDir(), g.ConfigFile)
}

func (g *Game) unitPath() string {
	if os.Getenv("GODEB_STEAM_ROOT") != "" {
		return filepath.Join(rootDir(), g.unit())
	}
	return filepath.Join("/etc/systemd/system", g.unit())
}

// installed reports whether the server binary exists (SteamCMD or copied in).
func (g *Game) installed() bool {
	_, err := os.Stat(g.executable())
	return err == nil
}

// ready reports whether the setup ran (the unit exists).
func (g *Game) ready() bool {
	_, err := os.Stat(g.unitPath())
	return err == nil
}

// readConfig reads the configuration file through the base root (never
// following a symlink out of it); os.ErrNotExist when there is none yet.
func (g *Game) readConfig() ([]byte, error) {
	if g.ConfigFile == "" {
		return nil, os.ErrNotExist
	}
	r, err := g.openBase()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return readLimited(r, g.configName(), maxConfigSize)
}

// currentConfig parses the configuration file, nil if there is none.
func (g *Game) currentConfig() map[string]any {
	if raw, err := g.readConfig(); err == nil {
		if cfg, err := g.ValidateConfig(raw); err == nil {
			return cfg
		}
	}
	return nil
}

// currentPorts reads the configuration if there is one.
func (g *Game) currentPorts() []int {
	return g.Ports(g.currentConfig())
}

// currentTCPPorts are the extra TCP ports, if the game has any.
func (g *Game) currentTCPPorts() []int {
	if g.TCPPorts == nil {
		return nil
	}
	return g.TCPPorts(g.currentConfig())
}

func (g *Game) String() string { return fmt.Sprintf("%s (App %s)", g.Name, g.AppID) }
