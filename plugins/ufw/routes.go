package ufw

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"godebplay/backend/core"
)

// RouteRule is one `ufw route allow` rule that GoDeb owns. Comment identifies
// it; rules whose comment starts with the owner's tag are reconciled by
// SyncRoutes and never touched otherwise.
type RouteRule struct {
	In      string // incoming interface
	Out     string // outgoing interface
	To      string // destination IPv4 address
	Port    string // "8080" or "15636:15637"
	Proto   string // "tcp" or "udp"
	Comment string
}

var (
	routeIface   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,14}$`)
	routePort    = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?$`)
	routeAddr    = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)
	routeComment = regexp.MustCompile(`^GoDeb-[A-Za-z]+ [A-Za-z0-9_.-]{1,48}$`)
)

func (r RouteRule) valid() error {
	switch {
	case !routeIface.MatchString(r.In) || !routeIface.MatchString(r.Out):
		return fmt.Errorf("ungültiges Interface %q/%q", r.In, r.Out)
	case !routeComment.MatchString(r.Comment):
		return fmt.Errorf("ungültiger Kommentar %q", r.Comment)
	}
	// Empty To/Port/Proto means all traffic (Volltunnel egress). Otherwise
	// all three must be set together, as for portforward and hub UI routes.
	allEmpty := r.To == "" && r.Port == "" && r.Proto == ""
	allSet := r.To != "" && r.Port != "" && r.Proto != ""
	switch {
	case allEmpty:
		return nil
	case !allSet:
		return fmt.Errorf("Ziel, Port und Protokoll müssen zusammen gesetzt sein oder alle leer")
	case !routeAddr.MatchString(r.To):
		return fmt.Errorf("ungültige Zieladresse %q", r.To)
	case !routePort.MatchString(r.Port):
		return fmt.Errorf("ungültiger Port %q", r.Port)
	case r.Proto != "tcp" && r.Proto != "udp":
		return fmt.Errorf("ungültiges Protokoll %q", r.Proto)
	}
	return nil
}

// args is the rule without the leading "route allow" / "route delete allow".
func (r RouteRule) args() []string {
	args := []string{"in", "on", r.In, "out", "on", r.Out}
	if r.To != "" {
		args = append(args, "to", r.To)
	}
	if r.Port != "" {
		args = append(args, "port", r.Port)
	}
	if r.Proto != "" {
		args = append(args, "proto", r.Proto)
	}
	return append(args, "comment", r.Comment)
}

// SyncRoutes makes the GoDeb route rules tagged with tag (for example
// "GoDeb-PF") equal to want: missing ones are added, stale ones deleted.
// Rules of other owners and hand-made rules stay untouched.
func SyncRoutes(ctx context.Context, tag string, want []RouteRule) error {
	prefix := tag + " "
	for _, r := range want {
		if err := r.valid(); err != nil {
			return err
		}
		if !strings.HasPrefix(r.Comment, prefix) {
			return fmt.Errorf("Kommentar %q gehört nicht zu %s", r.Comment, tag)
		}
	}
	res := core.RunAdmin(ctx, "ufw", "show", "added")
	if res.Err != nil {
		return &core.CommandError{Result: res}
	}
	have := ParseAddedRoutes(res.Stdout, tag)
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[r.Comment] = true
	}
	for comment, args := range have {
		if wanted[comment] {
			continue
		}
		del := append([]string{"--force", "route", "delete"}, args...)
		if res := core.RunAdmin(ctx, "ufw", del...); res.Err != nil {
			return &core.CommandError{Result: res}
		}
	}
	for _, r := range want {
		if _, ok := have[r.Comment]; ok {
			continue
		}
		add := append([]string{"route", "allow"}, r.args()...)
		if res := core.RunAdmin(ctx, "ufw", add...); res.Err != nil {
			return &core.CommandError{Result: res}
		}
	}
	return nil
}

// ParseAddedRoutes reads `ufw show added` and returns the route rules whose
// comment starts with tag, keyed by comment. The value is the rule as ufw
// printed it after "ufw route", so it can be passed to "ufw route delete".
func ParseAddedRoutes(out, tag string) map[string][]string {
	found := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ufw route ") {
			continue
		}
		args := splitQuoted(strings.TrimPrefix(line, "ufw route "))
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "comment" && strings.HasPrefix(args[i+1], tag+" ") {
				found[args[i+1]] = args
				break
			}
		}
	}
	return found
}

// splitQuoted splits on spaces and keeps 'single quoted' parts together, as
// ufw prints comments.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	quoted, inToken := false, false
	for _, c := range s {
		switch {
		case c == '\'':
			quoted = !quoted
			inToken = true
		case c == ' ' && !quoted:
			if inToken {
				out = append(out, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(c)
			inToken = true
		}
	}
	if inToken {
		out = append(out, cur.String())
	}
	return out
}
