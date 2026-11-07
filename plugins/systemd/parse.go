package systemd

import (
	"regexp"
	"strings"
)

// Service is one loaded systemd service unit.
type Service struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

var unitLine = regexp.MustCompile(`^(\S+\.service)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$`)

const sampleUnits = `cron.service loaded active running Regular background program processing daemon
ssh.service loaded active running OpenBSD Secure Shell server
nginx.service loaded inactive dead A high performance web server and a reverse proxy server
`

// ParseUnits keeps loaded service units from `systemctl list-units`.
func ParseUnits(out string) []Service {
	services := []Service{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		match := unitLine.FindStringSubmatch(line)
		if match == nil || match[2] != "loaded" {
			continue
		}
		services = append(services, Service{
			Unit:        match[1],
			Load:        match[2],
			Active:      match[3],
			Sub:         match[4],
			Description: strings.TrimSpace(match[5]),
		})
	}
	return services
}
