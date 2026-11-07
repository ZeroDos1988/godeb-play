// Package pluginmgr scans plugins/<id>/plugin.json and installs, enables or
// disables the declared apt packages and systemd units.
package pluginmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/db"
)

var (
	idPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,60}(:[a-z0-9]+)?$`)
	unitPattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:._@-]{0,120}\.(service|socket|timer)$`)
)

// execute is the OS command runner. Tests replace it.
var execute = func(ctx context.Context, timeout time.Duration, name string, args ...string) core.CommandResult {
	return core.RunAdminTimeout(ctx, timeout, name, args...)
}

// probe runs state queries (dpkg-query, systemctl is-*). Their non-zero
// exit is an answer ("not installed", "disabled"), so it is not logged as
// a failure. Tests replace it together with execute.
var probe = func(ctx context.Context, _ time.Duration, name string, args ...string) core.CommandResult {
	return core.RunAdminQuiet(ctx, name, args...)
}

// Descriptor is the on-disk plugin contract.
type Descriptor struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	AptDependencies []string `json:"apt_dependencies"`
	SystemdServices []string `json:"systemd_services"`
	// Architectures limits the plugin to these dpkg architectures (for
	// software that only exists for amd64). Empty means every architecture.
	Architectures []string `json:"architectures"`
	// Description comes from manifest.json next to plugin.json.
	Description string `json:"-"`
}

// hostArch is the dpkg architecture of this build. Tests replace it.
var hostArch = runtime.GOARCH

// Supported reports whether the plugin runs on this machine's architecture.
func (d Descriptor) Supported() bool {
	return len(d.Architectures) == 0 || slices.Contains(d.Architectures, hostArch)
}

// ServiceStatus is one systemd unit declared by a plugin.
type ServiceStatus struct {
	Unit    string `json:"unit"`
	Enabled string `json:"enabled"`
	Active  string `json:"active"`
}

// Plugin is the API view of one plugin directory.
type Plugin struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	AptDependencies   []string        `json:"aptDependencies"`
	SystemdServices   []string        `json:"systemdServices"`
	Supported         bool            `json:"supported"`
	Architectures     []string        `json:"architectures"`
	DependenciesReady bool            `json:"dependenciesReady"`
	Installed         bool            `json:"installed"`
	Enabled           bool            `json:"enabled"`
	Services          []ServiceStatus `json:"services"`
}

type stateRow struct {
	ID        string `gorm:"primaryKey"`
	Installed bool
	// Enabled is the legacy service flag; kept so old rows still load.
	Enabled bool
	// Disabled hides a plugin: no sidebar entry, its /api/plugins/<id>/
	// routes answer 404 and its services are stopped. Default: active.
	Disabled  bool
	UpdatedAt string
}

func (stateRow) TableName() string { return "plugin_states" }

var (
	dirMu      sync.Mutex
	mountedDir string
)

// SetDir remembers the plugin directory for InstallAndEnable. Mount sets it;
// the command line calls it itself.
func SetDir(pluginsDir string) {
	dirMu.Lock()
	mountedDir = pluginsDir
	dirMu.Unlock()
}

func currentDir() (string, error) {
	dirMu.Lock()
	defer dirMu.Unlock()
	if mountedDir == "" {
		return "", errors.New("Plugin-Verzeichnis ist nicht gesetzt")
	}
	return mountedDir, nil
}

// InstallAndEnable installs the APT packages of one plugin, if any are
// missing, and switches it on. The setup wizard uses it for the services
// it offers (mail gateway on a hub); it is the same path as the buttons of
// the plugin manager.
func InstallAndEnable(ctx context.Context, id string) error {
	dir, err := currentDir()
	if err != nil {
		return err
	}
	desc, err := Load(dir, id)
	if err != nil {
		return err
	}
	ready, err := PackagesReady(ctx, id)
	if err != nil {
		return err
	}
	if !ready {
		if err := install(ctx, dir, desc); err != nil {
			return err
		}
	}
	if err := enable(ctx, dir, desc); err != nil {
		return err
	}
	Reload()
	return nil
}

// PackagesReady reports whether every APT package of a plugin is installed.
func PackagesReady(ctx context.Context, id string) (bool, error) {
	dir, err := currentDir()
	if err != nil {
		return false, err
	}
	desc, err := Load(dir, id)
	if err != nil {
		return false, err
	}
	for _, pkg := range desc.AptDependencies {
		ok, err := packageInstalled(ctx, pkg)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// Mount registers scan, install, enable and disable.
func Mount(mux *http.ServeMux, pluginsDir string) {
	SetDir(pluginsDir)
	mux.HandleFunc("GET /api/plugin-manager", func(w http.ResponseWriter, r *http.Request) {
		writeScan(w, r, pluginsDir)
	})
	mux.HandleFunc("POST /api/plugin-manager/scan", func(w http.ResponseWriter, r *http.Request) {
		writeScan(w, r, pluginsDir)
	})
	mux.HandleFunc("POST /api/plugin-manager/{id}/install", func(w http.ResponseWriter, r *http.Request) {
		act(w, r, pluginsDir, install)
	})
	mux.HandleFunc("POST /api/plugin-manager/{id}/enable", func(w http.ResponseWriter, r *http.Request) {
		act(w, r, pluginsDir, enable)
	})
	mux.HandleFunc("POST /api/plugin-manager/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		act(w, r, pluginsDir, disable)
	})
}

func writeScan(w http.ResponseWriter, r *http.Request, pluginsDir string) {
	plugins, err := Scan(r.Context(), pluginsDir)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"plugins": plugins})
}

func act(w http.ResponseWriter, r *http.Request, pluginsDir string, fn func(context.Context, string, Descriptor) error) {
	id := r.PathValue("id")
	desc, err := Load(pluginsDir, id)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		core.WriteError(w, status, err.Error())
		return
	}
	if err := fn(r.Context(), pluginsDir, desc); err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	plugins, err := Scan(r.Context(), pluginsDir)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "plugins": plugins})
}

// Scan reads every plugin.json and resolves package and unit state.
func Scan(ctx context.Context, pluginsDir string) ([]Plugin, error) {
	descs, err := ReadAll(pluginsDir)
	if err != nil {
		return nil, err
	}
	remembered, err := loadStates()
	if err != nil {
		return nil, err
	}
	out := make([]Plugin, 0, len(descs))
	for _, desc := range descs {
		item, err := describe(ctx, desc, remembered[desc.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// ReadAll returns the parsed descriptors sorted by id.
func ReadAll(pluginsDir string) ([]Descriptor, error) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Descriptor{}, nil
		}
		return nil, fmt.Errorf("Plugin-Verzeichnis %s: %w", pluginsDir, err)
	}
	out := make([]Descriptor, 0)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "" || entry.Name()[0] == '.' {
			continue
		}
		path := filepath.Join(pluginsDir, entry.Name(), "plugin.json")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		desc, err := Load(pluginsDir, entry.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, desc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Load reads and validates one plugin.json.
func Load(pluginsDir, id string) (Descriptor, error) {
	if !idPattern.MatchString(id) {
		return Descriptor{}, fmt.Errorf("Plugin-ID %q ist ungültig", id)
	}
	raw, err := os.ReadFile(filepath.Join(pluginsDir, id, "plugin.json"))
	if err != nil {
		return Descriptor{}, err
	}
	var desc Descriptor
	if err := json.Unmarshal(raw, &desc); err != nil {
		return Descriptor{}, fmt.Errorf("plugin.json von %s: %w", id, err)
	}
	if desc.ID == "" {
		desc.ID = id
	}
	if desc.ID != id || !idPattern.MatchString(desc.ID) {
		return Descriptor{}, fmt.Errorf("plugin.json id %q passt nicht zum Ordner %s", desc.ID, id)
	}
	if desc.Name == "" {
		desc.Name = desc.ID
	}
	for _, pkg := range desc.AptDependencies {
		if !packagePattern.MatchString(pkg) {
			return Descriptor{}, fmt.Errorf("APT-Paketname %q ist ungültig", pkg)
		}
	}
	for _, unit := range desc.SystemdServices {
		if !unitPattern.MatchString(unit) || unit == "godeb-play.service" {
			return Descriptor{}, fmt.Errorf("systemd-Unit %q ist ungültig", unit)
		}
	}
	for _, arch := range desc.Architectures {
		if arch != "amd64" && arch != "arm64" {
			return Descriptor{}, fmt.Errorf("Architektur %q ist ungültig", arch)
		}
	}
	desc.Description = manifestDescription(pluginsDir, id)
	if desc.AptDependencies == nil {
		desc.AptDependencies = []string{}
	}
	if desc.Architectures == nil {
		desc.Architectures = []string{}
	}
	if desc.SystemdServices == nil {
		desc.SystemdServices = []string{}
	}
	return desc, nil
}

// manifestDescription reads the one-line description from manifest.json.
// It is only shown in the plugin list, so a missing or broken file is fine.
func manifestDescription(pluginsDir, id string) string {
	raw, err := os.ReadFile(filepath.Join(pluginsDir, id, "manifest.json"))
	if err != nil {
		return ""
	}
	var m struct {
		Description string `json:"description"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return strings.TrimSpace(m.Description)
}

func describe(ctx context.Context, desc Descriptor, remembered stateRow) (Plugin, error) {
	ready := true
	for _, pkg := range desc.AptDependencies {
		installed, err := packageInstalled(ctx, pkg)
		if err != nil {
			return Plugin{}, err
		}
		if !installed {
			ready = false
		}
	}
	services := make([]ServiceStatus, 0, len(desc.SystemdServices))
	for _, unit := range desc.SystemdServices {
		services = append(services, ServiceStatus{
			Unit:    unit,
			Enabled: unitProperty(ctx, "is-enabled", unit),
			Active:  unitProperty(ctx, "is-active", unit),
		})
	}
	installed := ready
	if len(desc.AptDependencies) == 0 {
		installed = true
	}
	if remembered.Installed {
		installed = installed || ready
	}
	return Plugin{
		ID:                desc.ID,
		Name:              desc.Name,
		Description:       desc.Description,
		AptDependencies:   desc.AptDependencies,
		SystemdServices:   desc.SystemdServices,
		Supported:         desc.Supported(),
		Architectures:     desc.Architectures,
		DependenciesReady: ready,
		Installed:         installed && ready,
		Enabled:           !remembered.Disabled,
		Services:          services,
	}, nil
}

// errUnsupported explains why a plugin cannot be installed on this machine.
func errUnsupported(desc Descriptor) error {
	return fmt.Errorf("%s läuft nur auf %s, dieser Server ist %s", desc.Name, strings.Join(desc.Architectures, ", "), hostArch)
}

func install(ctx context.Context, _ string, desc Descriptor) error {
	if !desc.Supported() {
		return errUnsupported(desc)
	}
	if len(desc.AptDependencies) > 0 {
		update := execute(ctx, 5*time.Minute, "apt-get", "update")
		if update.Err != nil {
			return fmt.Errorf("apt-get update: %s", update.Detail())
		}
		args := append([]string{"install", "-y", "--no-install-recommends"}, desc.AptDependencies...)
		res := execute(ctx, 20*time.Minute, "apt-get", args...)
		if res.Err != nil {
			return fmt.Errorf("apt-get install: %s", res.Detail())
		}
	}
	return updateState(desc.ID, func(r *stateRow) { r.Installed = true })
}

// enable shows the plugin again. Its packages must be installed; the
// system services it manages are left as they are.
func enable(ctx context.Context, _ string, desc Descriptor) error {
	if !desc.Supported() {
		return errUnsupported(desc)
	}
	for _, pkg := range desc.AptDependencies {
		ok, err := packageInstalled(ctx, pkg)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("Paket %s ist nicht installiert", pkg)
		}
	}
	return updateState(desc.ID, func(r *stateRow) { r.Installed, r.Enabled, r.Disabled = true, true, false })
}

// disable hides the plugin: no sidebar entry, its routes answer 404 and
// GoDeb's own background work for it (update checks, monitoring) pauses.
// The system services behind it keep running. Stopping wg-quick@wg0 or ufw
// here would cut the admin off the tunnel or open the firewall, and a unit
// that is not installed (postfix for the mail gateway) made switching off
// fail altogether.
func disable(_ context.Context, _ string, desc Descriptor) error {
	return updateState(desc.ID, func(r *stateRow) { r.Enabled, r.Disabled = false, true })
}

func packageInstalled(ctx context.Context, name string) (bool, error) {
	res := probe(ctx, 15*time.Second, "dpkg-query", "-W", "-f", "${db:Status-Status}", name)
	if res.Err != nil {
		if strings.Contains(res.Stderr, "no packages found") || strings.TrimSpace(res.Stdout) == "" {
			return false, nil
		}
		return false, nil
	}
	return strings.TrimSpace(res.Stdout) == "installed", nil
}

func unitProperty(ctx context.Context, verb, unit string) string {
	res := probe(ctx, 15*time.Second, "systemctl", verb, unit)
	value := strings.TrimSpace(res.Stdout)
	if value == "" {
		return "unknown"
	}
	return strings.Split(value, "\n")[0]
}

func loadStates() (map[string]stateRow, error) {
	gdb, err := db.AgentGorm()
	if err != nil {
		return nil, err
	}
	if err := gdb.AutoMigrate(&stateRow{}); err != nil {
		return nil, err
	}
	var rows []stateRow
	if err := gdb.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]stateRow, len(rows))
	for _, row := range rows {
		out[row.ID] = row
	}
	return out, nil
}

// updateState changes one plugin's row and refreshes the disabled cache.
func updateState(id string, edit func(*stateRow)) error {
	gdb, err := db.AgentGorm()
	if err != nil {
		return err
	}
	if err := gdb.AutoMigrate(&stateRow{}); err != nil {
		return err
	}
	row := stateRow{ID: id}
	if err := gdb.Where("id = ?", id).Limit(1).Find(&row).Error; err != nil {
		return err
	}
	row.ID = id
	edit(&row)
	row.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := gdb.Save(&row).Error; err != nil {
		return err
	}
	reloadDisabled()
	return nil
}

var disabledCache struct {
	sync.RWMutex
	loaded bool
	at     time.Time
	ids    map[string]bool
}

// disabledSource loads the switched-off plugins. The web process with a
// root agent replaces it with a call to the agent, which owns the state.
var disabledSource = DisabledIDs

// SetDisabledSource replaces where IsDisabled gets its list from.
func SetDisabledSource(fn func() (map[string]bool, error)) {
	disabledSource = fn
	reloadDisabled()
}

// DisabledIDs reads the switched-off plugins from the database.
func DisabledIDs() (map[string]bool, error) {
	rows, err := loadStates()
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for id, row := range rows {
		if row.Disabled {
			ids[id] = true
		}
	}
	return ids, nil
}

// disabledTTL bounds how stale the list in another process can get.
const disabledTTL = 30 * time.Second

func reloadDisabled() {
	ids, err := disabledSource()
	if err != nil {
		disabledCache.RLock()
		ids = disabledCache.ids
		disabledCache.RUnlock()
		if ids == nil {
			ids = map[string]bool{}
		}
	}
	disabledCache.Lock()
	disabledCache.ids, disabledCache.loaded, disabledCache.at = ids, true, time.Now()
	disabledCache.Unlock()
}

// Reload re-reads the switched-off plugins. The web process calls it after
// the agent changed them.
func Reload() {
	reloadDisabled()
}

// IsDisabled reports whether the plugin was switched off in the plugin
// manager. Unknown plugins and database errors count as active.
func IsDisabled(id string) bool {
	disabledCache.RLock()
	loaded, off, at := disabledCache.loaded, disabledCache.ids[id], disabledCache.at
	disabledCache.RUnlock()
	if loaded && time.Since(at) < disabledTTL {
		return off
	}
	reloadDisabled()
	disabledCache.RLock()
	defer disabledCache.RUnlock()
	return disabledCache.ids[id]
}
