package steam

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"path"
	"strings"
	"unicode"
)

// maxConfigSize bounds a game configuration. Enshrouded's is a few KiB.
const maxConfigSize = 60 << 10

const enshroudedQueryPort = 15637

func init() {
	register(&Game{
		ID:             "enshrouded",
		Name:           "Enshrouded",
		AppID:          "2278520",
		Platform:       Windows,
		Executable:     "enshrouded_server.exe",
		Packages:       []string{"wine"},
		StopSignal:     "SIGINT",
		DownloadGB:     8,
		MemoryGB:       8,
		ConfigFile:     "enshrouded_server.json",
		DefaultConfig:  enshroudedDefaultConfig,
		ValidateConfig: validateEnshrouded,
		Ports:          enshroudedPorts,
		QueryPort:      enshroudedQuery,
		SaveDir:        enshroudedSaveDir,
	})
}

// presets are the values the server accepts for gameSettingsPreset.
var presets = map[string]bool{"Default": true, "Relaxed": true, "Hard": true, "Survival": true, "Custom": true}

// enshroudedDefaultConfig is written on first install. Unknown keys that later server
// versions add are kept, because saves merge into the parsed file.
func enshroudedDefaultConfig() ([]byte, error) {
	admin, err := randomPassword()
	if err != nil {
		return nil, err
	}
	friend, err := randomPassword()
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"name":               "GoDeb Play Enshrouded",
		"saveDirectory":      "./savegame",
		"logDirectory":       "./logs",
		"ip":                 "0.0.0.0",
		"queryPort":          enshroudedQueryPort,
		"slotCount":          16,
		"tags":               []string{},
		"voiceChatMode":      "Proximity",
		"enableVoiceChat":    false,
		"enableTextChat":     false,
		"gameSettingsPreset": "Default",
		"userGroups": []map[string]any{
			{"name": "Admin", "password": admin, "canKickBan": true, "canAccessInventories": true, "canEditBase": true, "canExtendBase": true, "reservedSlots": 0},
			{"name": "Friend", "password": friend, "canKickBan": false, "canAccessInventories": true, "canEditBase": true, "canExtendBase": false, "reservedSlots": 0},
		},
	}
	return marshalConfig(cfg)
}

func marshalConfig(cfg map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// validateEnshrouded checks the keys GoDeb shows in the form and leaves all
// other keys alone. It returns the parsed object.
func validateEnshrouded(raw []byte) (map[string]any, error) {
	cfg, err := parseConfigObject(raw)
	if err != nil {
		return nil, err
	}
	if v, ok := cfg["name"]; ok {
		name, ok := v.(string)
		if !ok || strings.TrimSpace(name) == "" || len(name) > 64 || hasControl(name) {
			return nil, fmt.Errorf("name: 1 bis 64 Zeichen ohne Steuerzeichen")
		}
	}
	for _, key := range []string{"queryPort", "gamePort"} {
		if v, ok := cfg[key]; ok {
			if n, ok := intValue(v); !ok || n < 1024 || n > 65535 {
				return nil, fmt.Errorf("%s muss zwischen 1024 und 65535 liegen", key)
			}
		}
	}
	if v, ok := cfg["slotCount"]; ok {
		if n, ok := intValue(v); !ok || n < 1 || n > 16 {
			return nil, fmt.Errorf("slotCount muss zwischen 1 und 16 liegen")
		}
	}
	if v, ok := cfg["ip"]; ok {
		ip, ok := v.(string)
		if !ok || net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("ip muss eine IP-Adresse sein")
		}
	}
	for _, key := range []string{"saveDirectory", "logDirectory"} {
		if v, ok := cfg[key]; ok {
			dir, ok := v.(string)
			if !ok || !safeRelative(dir) {
				return nil, fmt.Errorf("%s muss ein relativer Pfad im Serververzeichnis sein", key)
			}
		}
	}
	if v, ok := cfg["gameSettingsPreset"]; ok {
		preset, ok := v.(string)
		if !ok || !presets[preset] {
			return nil, fmt.Errorf("gameSettingsPreset muss Default, Relaxed, Hard, Survival oder Custom sein")
		}
	}
	if v, ok := cfg["gameSettings"]; ok {
		if err := validateGameSettings(v); err != nil {
			return nil, err
		}
	}
	for _, key := range []string{"enableVoiceChat", "enableTextChat"} {
		if v, ok := cfg[key]; ok {
			if _, ok := v.(bool); !ok {
				return nil, fmt.Errorf("%s muss true oder false sein", key)
			}
		}
	}
	if v, ok := cfg["userGroups"]; ok {
		if err := validateGroups(v); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// Known Custom preset factors (float). Unknown keys are kept as-is if they
// are numbers in 0.1–10, so newer server fields survive a round-trip.
func validateGameSettings(v any) error {
	obj, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("gameSettings muss ein Objekt sein")
	}
	if len(obj) > 64 {
		return fmt.Errorf("zu viele gameSettings")
	}
	for key, raw := range obj {
		if hasControl(key) || len(key) > 64 {
			return fmt.Errorf("gameSettings-Schlüssel ungültig")
		}
		n, ok := floatValue(raw)
		if !ok || n < 0.1 || n > 10 {
			return fmt.Errorf("gameSettings.%s muss eine Zahl zwischen 0,1 und 10 sein", key)
		}
	}
	return nil
}

func floatValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func validateGroups(v any) error {
	groups, ok := v.([]any)
	if !ok {
		return fmt.Errorf("userGroups muss eine Liste sein")
	}
	if len(groups) > 16 {
		return fmt.Errorf("höchstens 16 Benutzergruppen")
	}
	seen := map[string]bool{}
	for i, item := range groups {
		group, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("userGroups[%d] muss ein Objekt sein", i)
		}
		name, ok := group["name"].(string)
		if !ok || strings.TrimSpace(name) == "" || len(name) > 32 || hasControl(name) {
			return fmt.Errorf("userGroups[%d].name: 1 bis 32 Zeichen", i)
		}
		if seen[name] {
			return fmt.Errorf("Gruppe %s ist doppelt", name)
		}
		seen[name] = true
		if pw, ok := group["password"]; ok {
			s, ok := pw.(string)
			if !ok || len(s) > 64 || hasControl(s) {
				return fmt.Errorf("Passwort der Gruppe %s: höchstens 64 Zeichen ohne Steuerzeichen", name)
			}
		}
		for _, key := range []string{"canKickBan", "canAccessInventories", "canEditBase", "canExtendBase"} {
			if b, ok := group[key]; ok {
				if _, ok := b.(bool); !ok {
					return fmt.Errorf("%s der Gruppe %s muss true oder false sein", key, name)
				}
			}
		}
		if r, ok := group["reservedSlots"]; ok {
			if n, ok := intValue(r); !ok || n < 0 || n > 16 {
				return fmt.Errorf("reservedSlots der Gruppe %s muss zwischen 0 und 16 liegen", name)
			}
		}
	}
	return nil
}

// enshroudedQuery is the configured queryPort, else the default.
// enshroudedSaveDir is saveDirectory from the configuration (validated as
// a relative path in the server directory), ./savegame by default.
func enshroudedSaveDir(cfg map[string]any) string {
	if dir, ok := cfg["saveDirectory"].(string); ok && safeRelative(dir) {
		return path.Join(serverSub, dir)
	}
	return path.Join(serverSub, "savegame")
}

func enshroudedQuery(cfg map[string]any) int {
	if n, ok := intValue(cfg["queryPort"]); ok && n > 0 && n < 65536 {
		return n
	}
	return enshroudedQueryPort
}

// enshroudedPorts lists the UDP ports to open. Older server builds use
// queryPort-1 as game port without a gamePort key, so that one is opened too.
func enshroudedPorts(cfg map[string]any) []int {
	out := []int{}
	for _, key := range []string{"gamePort", "queryPort"} {
		if n, ok := intValue(cfg[key]); ok {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = append(out, enshroudedQueryPort)
	}
	if _, ok := cfg["gamePort"]; !ok && len(out) == 1 && out[0] > 1024 {
		out = append([]int{out[0] - 1}, out...)
	}
	return out
}

// parseConfigObject decodes a JSON object with numbers kept exact. Shared by
// every game whose configuration is JSON.
func parseConfigObject(raw []byte) (map[string]any, error) {
	if len(raw) > maxConfigSize {
		return nil, fmt.Errorf("Konfiguration ist größer als %d KiB", maxConfigSize>>10)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var cfg map[string]any
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("Kein gültiges JSON: %v", err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("Konfiguration muss ein JSON-Objekt sein")
	}
	if dec.More() {
		return nil, fmt.Errorf("Nach dem JSON-Objekt folgt weiterer Text")
	}
	return cfg, nil
}

func intValue(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	case float64:
		return int(n), n == float64(int(n))
	case int:
		return n, true
	}
	return 0, false
}

func safeRelative(dir string) bool {
	if dir == "" || strings.HasPrefix(dir, "/") || strings.Contains(dir, "\\") || hasControl(dir) {
		return false
	}
	clean := path.Clean(dir)
	return clean != ".." && !strings.HasPrefix(clean, "../")
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

func randomPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 16)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}
