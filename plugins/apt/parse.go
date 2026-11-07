package apt

import (
	"regexp"
	"strings"
)

// Package is one upgradable Debian package.
type Package struct {
	Name    string `json:"name"`
	Suite   string `json:"suite"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	From    string `json:"from"`
	// Security is set when the candidate comes from a security suite
	// (e.g. trixie-security).
	Security bool `json:"security"`
}

var aptLine = regexp.MustCompile(`^([a-z0-9][a-z0-9+.-]*)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from:\s*([^\]]+)\]\s*$`)

const sampleUpgradable = `Listing...
bash/stable 5.2.37-2+b3 amd64 [upgradable from: 5.2.37-2]
openssl/stable-security 3.5.7-1 amd64 [upgradable from: 3.5.4-1]
`

// ParseUpgradable extracts package rows from `apt list --upgradable`.
func ParseUpgradable(out string) []Package {
	packages := []Package{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		match := aptLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		packages = append(packages, Package{
			Name:     match[1],
			Suite:    match[2],
			Version:  match[3],
			Arch:     match[4],
			From:     strings.TrimSpace(match[5]),
			Security: securitySuite(match[2]),
		})
	}
	return packages
}

// securitySuite reports whether one of the comma-separated suites apt
// lists for the candidate is a security suite.
func securitySuite(suites string) bool {
	for _, s := range strings.Split(suites, ",") {
		if strings.HasSuffix(s, "-security") {
			return true
		}
	}
	return false
}
