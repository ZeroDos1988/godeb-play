package wireguard

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// A site profile tells a site what it becomes when it joins. The GoDeb hub
// writes it as comments into the client file (and so into the join code);
// GoDeb Play checks it like GoDeb does and keeps it in its wg0.conf. Copy of
// GoDeb's plugins/wireguard/profile.go: keep both in sync.
const (
	// ProfileHome is a GoDeb home server: mailboxes, spam filter, virus
	// scanner, websites and databases. The hub keeps DNS, certificates and
	// the mail entry and exit.
	ProfileHome = "home"
	// ProfilePlay is a GoDeb Play host with game servers.
	ProfilePlay = "play"

	profileMarker     = "GoDeb-Profile"
	mailHostMarker    = "GoDeb-Mail-Host"
	mailDomainsMarker = "GoDeb-Mail-Domains"
	maxMailDomains    = 20
)

// SiteProfile is the profile of a site. The zero value is a plain site.
type SiteProfile struct {
	Kind string `json:"kind,omitempty"`
	// MailHost is the name mail programs use for the mailboxes of a home
	// server; its A record points to the site's tunnel address.
	MailHost string `json:"mailHost,omitempty"`
	// MailDomains are the domains whose mail the hub hands to the site.
	MailDomains []string `json:"mailDomains,omitempty"`
}

// Normalize lowercases the names and checks the profile. Every value ends
// up in wg0.conf comments and later in the mail configuration, so only
// plain host names pass.
func (p SiteProfile) Normalize() (SiteProfile, error) {
	p.Kind = strings.ToLower(strings.TrimSpace(p.Kind))
	switch p.Kind {
	case "", ProfilePlay:
		if p.MailHost != "" || len(p.MailDomains) > 0 {
			return p, errors.New("Mail-Host und Mail-Domains gibt es nur beim Profil Heim-Server")
		}
		return p, nil
	case ProfileHome:
	default:
		return p, fmt.Errorf("Profil %q ist unbekannt (home oder play)", p.Kind)
	}
	if p.MailHost == "" && len(p.MailDomains) == 0 {
		return p, nil
	}
	host, err := profileName(p.MailHost)
	if err != nil {
		return p, fmt.Errorf("Mail-Host: %w", err)
	}
	p.MailHost = host
	if len(p.MailDomains) == 0 {
		return p, errors.New("Mail-Domains fehlen")
	}
	if len(p.MailDomains) > maxMailDomains {
		return p, fmt.Errorf("höchstens %d Mail-Domains", maxMailDomains)
	}
	out := make([]string, 0, len(p.MailDomains))
	for _, raw := range p.MailDomains {
		d, err := profileName(raw)
		if err != nil {
			return p, fmt.Errorf("Mail-Domain: %w", err)
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	p.MailDomains = out
	return p, nil
}

// profileName accepts a host name with at least one dot.
func profileName(raw string) (string, error) {
	v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(v) > 253 || !strings.Contains(v, ".") || !hostName.MatchString(v) {
		return "", fmt.Errorf("%q ist kein Hostname", raw)
	}
	return v, nil
}

// comments renders the profile as comment lines; empty for a plain site.
func (p SiteProfile) comments() string {
	if p.Kind == "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n", profileMarker, p.Kind)
	if p.MailHost != "" {
		fmt.Fprintf(&b, "# %s: %s\n", mailHostMarker, p.MailHost)
		fmt.Fprintf(&b, "# %s: %s\n", mailDomainsMarker, strings.Join(p.MailDomains, ", "))
	}
	return b.String()
}

// readProfileComment takes over one profile comment line; false if the
// line is none.
func readProfileComment(line string, p *SiteProfile) bool {
	if !strings.HasPrefix(line, "#") {
		return false
	}
	if v, ok := commentValue(line, profileMarker); ok {
		p.Kind = v
	} else if v, ok := commentValue(line, mailHostMarker); ok {
		p.MailHost = v
	} else if v, ok := commentValue(line, mailDomainsMarker); ok {
		p.MailDomains = splitList(v)
	} else {
		return false
	}
	return true
}

// profileFrom reads the profile comments of a configuration. Invalid
// values give the zero profile, so a hand-edited file cannot smuggle names
// into the setup.
func profileFrom(content string) SiteProfile {
	var p SiteProfile
	for _, line := range strings.Split(content, "\n") {
		readProfileComment(strings.TrimSpace(line), &p)
	}
	clean, err := p.Normalize()
	if err != nil {
		return SiteProfile{}
	}
	return clean
}

// JoinProfile reads the profile of a client file or join code without
// joining; the zero profile when there is none or the input is invalid.
func JoinProfile(input string) SiteProfile {
	content, err := decodeJoinInput(input)
	if err != nil {
		return SiteProfile{}
	}
	jc, _, err := parseJoinConfig(content)
	if err != nil {
		return SiteProfile{}
	}
	return jc.Profile
}
