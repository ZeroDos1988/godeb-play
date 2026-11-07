package ufw

import (
	"regexp"
	"strings"
)

// Rule is one displayed firewall rule.
type Rule struct {
	To     string `json:"to"`
	Action string `json:"action"`
	From   string `json:"from"`
}

// Status is the parsed `ufw status` output.
type Status struct {
	Active bool   `json:"active"`
	Rules  []Rule `json:"rules"`
}

var ufwRule = regexp.MustCompile(`^(.+?)\s{2,}((?:ALLOW|DENY|REJECT|LIMIT)(?:\s+(?:IN|OUT))?)\s{2,}(\S.*?)\s*$`)

const sampleStatus = `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
`

// ParseStatus reads the human table from `ufw status`.
func ParseStatus(out string) Status {
	status := Status{Rules: []Rule{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Status:") {
			value := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Status:")))
			status.Active = value == "active"
			continue
		}
		if line == "" || strings.HasPrefix(line, "To ") || strings.HasPrefix(line, "--") {
			continue
		}
		match := ufwRule.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		status.Rules = append(status.Rules, Rule{
			To:     strings.TrimSpace(match[1]),
			Action: strings.TrimSpace(match[2]),
			From:   strings.TrimSpace(match[3]),
		})
	}
	return status
}
