package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

// pluginID matches the directory name and the URL segment under /api/plugins/.
var pluginID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Meta is the public description of a discovered plugin.
type Meta struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Group       string `json:"group"`
	Order       int    `json:"order"`
	Ready       bool   `json:"ready"`
}

// pluginGroups are the tabs of the top navigation. A manifest without a
// known group lands under "apps".
var pluginGroups = map[string]bool{"system": true, "network": true, "apps": true}

type manifestFile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Group       string `json:"group"`
	Order       int    `json:"order"`
}

// Registry maps a plugin id to the function that mounts its routes and,
// optionally, a background service.
type Registry struct {
	handlers map[string]func(mux *http.ServeMux)
	services map[string]func(ctx context.Context)
	mu       sync.Mutex
	mounted  map[string]bool
}

// NewRegistry returns an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{handlers: map[string]func(mux *http.ServeMux){}}
}

// Default is the process-wide registry filled from plugin init functions.
var Default = NewRegistry()

// Register adds a route mounter for a plugin id. Later registrations replace earlier ones.
func Register(id string, mount func(mux *http.ServeMux)) {
	Default.Register(id, mount)
}

// RegisterService adds a background service for a plugin id. It runs only
// in the process that mounts the plugin (the agent), and only after
// StartServices.
func RegisterService(id string, run func(ctx context.Context)) {
	Default.RegisterService(id, run)
}

// RegisterService adds a background service for a plugin id.
func (r *Registry) RegisterService(id string, run func(ctx context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.services == nil {
		r.services = map[string]func(ctx context.Context){}
	}
	r.services[id] = run
}

// StartServices starts the services of every plugin mounted by Load. They
// stop when ctx ends.
func (r *Registry) StartServices(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, run := range r.services {
		if r.mounted[id] {
			go run(ctx)
		}
	}
}

// Register adds a route mounter for a plugin id.
func (r *Registry) Register(id string, mount func(mux *http.ServeMux)) {
	if r.handlers == nil {
		r.handlers = map[string]func(mux *http.ServeMux){}
	}
	r.handlers[id] = mount
}

// Scan returns the sidebar metadata like Load without mounting anything.
// The web process uses it when the root agent serves the plugin routes, so
// no plugin code (and no background goroutine) runs there.
func (r *Registry) Scan(pluginsDir string) ([]Meta, error) {
	return r.Load(pluginsDir, nil)
}

// Load scans pluginsDir, mounts routes for plugins that have both a manifest
// and a registered handler, and returns the sidebar metadata. A nil mux only
// scans.
func (r *Registry) Load(pluginsDir string, mux *http.ServeMux) ([]Meta, error) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Meta{}, nil
		}
		return nil, fmt.Errorf("Plugin-Verzeichnis %s: %w", pluginsDir, err)
	}

	metas := make([]Meta, 0)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "" || entry.Name()[0] == '.' {
			continue
		}
		meta, ok := r.loadOne(pluginsDir, entry.Name(), mux)
		if !ok {
			continue
		}
		metas = append(metas, meta)
	}
	sort.Slice(metas, func(i, j int) bool {
		if metas[i].Order == metas[j].Order {
			return metas[i].ID < metas[j].ID
		}
		return metas[i].Order < metas[j].Order
	})
	return metas, nil
}

func (r *Registry) loadOne(pluginsDir, name string, mux *http.ServeMux) (Meta, bool) {
	raw, err := os.ReadFile(filepath.Join(pluginsDir, name, "manifest.json"))
	if err != nil {
		slog.Warn("manifest.json fehlt", "plugin", name, "fehler", err)
		return Meta{}, false
	}
	var file manifestFile
	if err := json.Unmarshal(raw, &file); err != nil {
		slog.Warn("manifest.json ungültig", "plugin", name, "fehler", err)
		return Meta{}, false
	}
	if file.ID == "" {
		file.ID = name
	}
	if file.ID != name || !pluginID.MatchString(file.ID) {
		slog.Warn("Plugin-ID passt nicht zum Ordnernamen", "plugin", name, "id", file.ID)
		return Meta{}, false
	}
	if file.Name == "" {
		file.Name = file.ID
	}
	if file.Order == 0 {
		file.Order = 100
	}
	if !pluginGroups[file.Group] {
		file.Group = "apps"
	}
	meta := Meta{
		ID:          file.ID,
		Name:        file.Name,
		Description: file.Description,
		Icon:        file.Icon,
		Group:       file.Group,
		Order:       file.Order,
	}
	mount := r.handlers[file.ID]
	if mount == nil {
		slog.Warn("Plugin-Ordner ohne registrierten Handler", "plugin", file.ID)
		return meta, true
	}
	if mux != nil {
		mount(mux)
		r.mu.Lock()
		if r.mounted == nil {
			r.mounted = map[string]bool{}
		}
		r.mounted[file.ID] = true
		r.mu.Unlock()
	}
	meta.Ready = true
	return meta, true
}
