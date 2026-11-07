package steam

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Valheim's dedicated server takes everything on the command line. GoDeb
// Play keeps the settings in godeb-valheim.json (form and file view) and
// hands them to the server through the root-only settings file, so the
// password never sits in a file the game account owns.

const valheimPort = 2456

var (
	valheimWorld    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	valheimName     = regexp.MustCompile(`^[A-Za-z0-9 _.,!?()+-]{3,32}$`)
	valheimPassword = regexp.MustCompile(`^[A-Za-z0-9_.,!?@#+=-]{5,32}$`)
)

func init() {
	register(&Game{
		ID:         "valheim",
		Name:       "Valheim",
		AppID:      "896660",
		Platform:   Linux,
		Executable: "valheim_server.x86_64",
		Args: []string{
			"-nographics", "-batchmode",
			"-name", "${VALHEIM_NAME}",
			"-port", "${VALHEIM_PORT}",
			"-world", "${VALHEIM_WORLD}",
			"-password", "${VALHEIM_PASSWORD}",
			"-public", "${VALHEIM_PUBLIC}",
		},
		Packages:       []string{"libatomic1", "libpulse0"},
		StopSignal:     "SIGINT",
		DownloadGB:     2,
		MemoryGB:       4,
		ConfigFile:     "godeb-valheim.json",
		DefaultConfig:  valheimDefaultConfig,
		ValidateConfig: validateValheim,
		Ports:          valheimPorts,
		QueryPort:      valheimQuery,
		// HOME is the base directory, so Unity keeps the worlds there.
		SaveDir:  func(map[string]any) string { return ".config/unity3d/IronGate/Valheim" },
		LibDirs:  []string{"linux64"},
		UnitEnv:  []string{"SteamAppId=892970"},
		Settings: valheimSettings,
	})
}

func valheimDefaultConfig() ([]byte, error) {
	pw, err := randomPassword()
	if err != nil {
		return nil, err
	}
	return marshalConfig(map[string]any{
		"name":     "GoDeb Play Valheim",
		"world":    "Dedicated",
		"password": pw,
		"public":   false,
		"port":     valheimPort,
	})
}

// validateValheim checks the settings the server needs. Valheim refuses a
// password shorter than five characters or one that contains the server
// name.
func validateValheim(raw []byte) (map[string]any, error) {
	cfg, err := parseConfigObject(raw)
	if err != nil {
		return nil, err
	}
	name, _ := cfg["name"].(string)
	if !valheimName.MatchString(name) {
		return nil, fmt.Errorf("name: 3 bis 32 Zeichen, Buchstaben, Ziffern, Leerzeichen und _ . , ! ? ( ) + -")
	}
	world, _ := cfg["world"].(string)
	if !valheimWorld.MatchString(world) {
		return nil, fmt.Errorf("world: 1 bis 32 Zeichen, Buchstaben, Ziffern, _ und -")
	}
	pw, _ := cfg["password"].(string)
	if !valheimPassword.MatchString(pw) {
		return nil, fmt.Errorf("password: 5 bis 32 Zeichen, Buchstaben, Ziffern und _ . , ! ? @ # + = -")
	}
	if strings.Contains(strings.ToLower(pw), strings.ToLower(name)) {
		return nil, fmt.Errorf("password darf den Servernamen nicht enthalten")
	}
	if v, ok := cfg["public"]; ok {
		if _, ok := v.(bool); !ok {
			return nil, fmt.Errorf("public muss true oder false sein")
		}
	}
	if v, ok := cfg["port"]; ok {
		if n, ok := intValue(v); !ok || n < 1024 || n > 65534 {
			return nil, fmt.Errorf("port muss zwischen 1024 und 65534 liegen")
		}
	}
	return cfg, nil
}

func valheimPort0(cfg map[string]any) int {
	if n, ok := intValue(cfg["port"]); ok && n >= 1024 && n <= 65534 {
		return n
	}
	return valheimPort
}

// valheimPorts: the game port and the next one (Steam query).
func valheimPorts(cfg map[string]any) []int {
	p := valheimPort0(cfg)
	return []int{p, p + 1}
}

func valheimQuery(cfg map[string]any) int { return valheimPort0(cfg) + 1 }

func valheimSettings(cfg map[string]any) (map[string]string, error) {
	public := "0"
	if b, _ := cfg["public"].(bool); b {
		public = "1"
	}
	name, _ := cfg["name"].(string)
	world, _ := cfg["world"].(string)
	pw, _ := cfg["password"].(string)
	return map[string]string{
		"VALHEIM_NAME":     name,
		"VALHEIM_WORLD":    world,
		"VALHEIM_PASSWORD": pw,
		"VALHEIM_PUBLIC":   public,
		"VALHEIM_PORT":     strconv.Itoa(valheimPort0(cfg)),
	}, nil
}
