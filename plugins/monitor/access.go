package monitor

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/metrics"
	"godebplay/plugins/logs"
)

func init() {
	extraRoutes = append(extraRoutes, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/plugins/monitor/access", handleAccess)
	})
}

// accessRanges are shorter than chart ranges: the journal is read on demand.
var accessRanges = map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

// AccessEntry is one access to the host: an SSH or GoDeb sign-in, a GoDeb
// change, a fail2ban ban.
type AccessEntry struct {
	Time   int64  `json:"time"` // unix seconds
	Kind   string `json:"kind"` // ssh, login, logout, action, ban
	OK     bool   `json:"ok"`
	User   string `json:"user,omitempty"`
	IP     string `json:"ip,omitempty"`
	Name   string `json:"name,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// AccessStats counts what happened in the window.
type AccessStats struct {
	SSHOK       int `json:"sshOk"`
	SSHFailed   int `json:"sshFailed"`
	LoginOK     int `json:"loginOk"`
	LoginFailed int `json:"loginFailed"`
	Actions     int `json:"actions"`
	Bans        int `json:"bans"`
	Blocks      int `json:"blocks"`
}

// Source is an address with a count, for the top lists.
type Source struct {
	IP    string   `json:"ip"`
	Name  string   `json:"name,omitempty"`
	Count int      `json:"count"`
	Ports []string `json:"ports,omitempty"`
}

type accessResponse struct {
	Entries    []AccessEntry `json:"entries"`
	Stats      AccessStats   `json:"stats"`
	TopBlocked []Source      `json:"topBlocked"`
	TopFailed  []Source      `json:"topFailed"`
	Notes      []string      `json:"notes,omitempty"`
	Mocked     bool          `json:"mocked"`
}

var (
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (\S+) from (\S+) port \d+`)
	sshInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+) port \d+`)
	f2bBan      = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[([^\]]+)\] Ban (\S+)`)
	f2bBanJrnl  = regexp.MustCompile(`NOTICE\s+\[([^\]]+)\] Ban (\S+)`)
	ufwField    = regexp.MustCompile(`\b(SRC|DPT|PROTO)=(\S+)`)
)

// cleanIP keeps only well-formed addresses from log lines.
func cleanIP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// cleanUser shortens a user name from a log line; attackers pick them.
func cleanUser(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 32 {
			break
		}
		if r > 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseSSH turns sshd journal entries into access entries.
func ParseSSH(entries []logs.Entry) []AccessEntry {
	var out []AccessEntry
	for _, e := range entries {
		t := e.Time / 1000
		if m := sshAccepted.FindStringSubmatch(e.Message); m != nil {
			out = append(out, AccessEntry{Time: t, Kind: "ssh", OK: true, User: cleanUser(m[2]), IP: cleanIP(m[3]), Detail: m[1]})
		} else if m := sshFailed.FindStringSubmatch(e.Message); m != nil && m[2] != "invalid" {
			out = append(out, AccessEntry{Time: t, Kind: "ssh", User: cleanUser(m[2]), IP: cleanIP(m[3]), Detail: m[1]})
		} else if m := sshInvalid.FindStringSubmatch(e.Message); m != nil {
			out = append(out, AccessEntry{Time: t, Kind: "ssh", User: cleanUser(m[1]), IP: cleanIP(m[2]), Detail: "unbekannter Benutzer"})
		}
	}
	return out
}

// ParseGoDeb picks sign-ins, sign-outs and changes from GoDeb's own log.
func ParseGoDeb(entries []logs.Entry) []AccessEntry {
	var out []AccessEntry
	for _, e := range entries {
		f := map[string]string{}
		for _, kv := range e.Fields {
			f[kv.Key] = kv.Value
		}
		a := AccessEntry{Time: e.Time / 1000, User: cleanUser(f["benutzer"]), IP: cleanIP(f["ip"])}
		switch e.Message {
		case "Anmeldung erfolgreich":
			a.Kind, a.OK = "login", true
		case "Anmeldung fehlgeschlagen":
			a.Kind = "login"
		case "Abmeldung":
			a.Kind, a.OK = "logout", true
		case "Aktion", "Aktion abgelehnt", "Aktion fehlgeschlagen":
			if e.Unit != "godeb-play-agent.service" && f["benutzer"] == "" {
				continue
			}
			a.Kind, a.OK = "action", e.Message == "Aktion"
			a.Detail = strings.TrimSpace(f["methode"] + " " + f["pfad"] + " " + f["status"])
		default:
			continue
		}
		out = append(out, a)
	}
	return out
}

// ParseFail2banLog reads Ban lines of /var/log/fail2ban.log since a time.
func ParseFail2banLog(r io.Reader, since time.Time) []AccessEntry {
	var out []AccessEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 16<<10), 1<<20)
	for sc.Scan() {
		m := f2bBan.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
		if err != nil || t.Before(since) {
			continue
		}
		out = append(out, AccessEntry{Time: t.Unix(), Kind: "ban", IP: cleanIP(m[3]), Detail: m[2]})
	}
	return out
}

// ParseUFW counts kernel [UFW BLOCK] lines per source and port.
func ParseUFW(entries []logs.Entry) (int, []Source) {
	bySrc := map[string]*Source{}
	total := 0
	for _, e := range entries {
		if !strings.Contains(e.Message, "UFW BLOCK") {
			continue
		}
		var src, port, proto string
		for _, m := range ufwField.FindAllStringSubmatch(e.Message, -1) {
			switch m[1] {
			case "SRC":
				src = cleanIP(m[2])
			case "DPT":
				port = m[2]
			case "PROTO":
				proto = strings.ToLower(m[2])
			}
		}
		if src == "" {
			continue
		}
		total++
		s := bySrc[src]
		if s == nil {
			s = &Source{IP: src}
			bySrc[src] = s
		}
		s.Count++
		if port != "" {
			if _, err := strconv.Atoi(port); err == nil {
				label := proto + "/" + port
				if !containsString(s.Ports, label) && len(s.Ports) < 5 {
					s.Ports = append(s.Ports, label)
				}
			}
		}
	}
	return total, topSources(bySrc, 10)
}

func topSources(m map[string]*Source, n int) []Source {
	out := make([]Source, 0, len(m))
	for _, s := range m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func journal(ctx context.Context, since string, lines int, extra ...string) ([]logs.Entry, bool) {
	args := append([]string{"--no-pager", "--quiet", "--output=json", "--since=" + since, "--lines=" + strconv.Itoa(lines)}, extra...)
	out, env := core.ReadCommand(ctx, "", "journalctl", args...)
	if env.Mocked {
		return nil, false
	}
	return logs.ParseJournal(out), true
}

const maxAccessEntries = 300

func handleAccess(w http.ResponseWriter, r *http.Request) {
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	window, ok := accessRanges[rangeName]
	since := "-" + strconv.Itoa(int(window/time.Second)) + "s"
	if !ok {
		core.WriteError(w, http.StatusBadRequest, "Ungültiger Zeitraum")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	resp := accessResponse{Entries: []AccessEntry{}, TopBlocked: []Source{}, TopFailed: []Source{}}
	var entries []AccessEntry

	ssh, okSSH := journal(ctx, since, 5000, "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session")
	godeb, okGoDeb := journal(ctx, since, 5000, "--unit=godeb-play.service", "--unit=godeb-play-agent.service")
	if !okSSH && !okGoDeb {
		resp.Mocked = true
		resp.Notes = append(resp.Notes, "journalctl nicht lesbar")
		ssh, godeb = sampleSSH(), nil
	}
	entries = append(entries, ParseSSH(ssh)...)
	entries = append(entries, ParseGoDeb(godeb)...)

	if f, err := os.Open("/var/log/fail2ban.log"); err == nil {
		entries = append(entries, ParseFail2banLog(f, time.Now().Add(-window))...)
		f.Close()
	}
	if f2b, ok := journal(ctx, since, 2000, "--unit=fail2ban.service"); ok {
		for _, e := range f2b {
			if m := f2bBanJrnl.FindStringSubmatch(e.Message); m != nil {
				entries = append(entries, AccessEntry{Time: e.Time / 1000, Kind: "ban", IP: cleanIP(m[2]), Detail: m[1]})
			}
		}
	}
	if kernel, ok := journal(ctx, since, 20000, "--dmesg", "--grep=UFW BLOCK"); ok {
		resp.Stats.Blocks, resp.TopBlocked = ParseUFW(kernel)
	}

	names := metrics.AddressNames()
	failed := map[string]*Source{}
	for i := range entries {
		e := &entries[i]
		e.Name = names[e.IP]
		switch {
		case e.Kind == "ssh" && e.OK:
			resp.Stats.SSHOK++
		case e.Kind == "ssh":
			resp.Stats.SSHFailed++
		case e.Kind == "login" && e.OK:
			resp.Stats.LoginOK++
		case e.Kind == "login":
			resp.Stats.LoginFailed++
		case e.Kind == "action":
			resp.Stats.Actions++
		case e.Kind == "ban":
			resp.Stats.Bans++
		}
		if !e.OK && (e.Kind == "ssh" || e.Kind == "login") && e.IP != "" {
			s := failed[e.IP]
			if s == nil {
				s = &Source{IP: e.IP, Name: e.Name}
				failed[e.IP] = s
			}
			s.Count++
		}
	}
	for i := range resp.TopBlocked {
		resp.TopBlocked[i].Name = names[resp.TopBlocked[i].IP]
	}
	resp.TopFailed = topSources(failed, 10)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time > entries[j].Time })
	if len(entries) > maxAccessEntries {
		entries = entries[:maxAccessEntries]
	}
	if entries != nil {
		resp.Entries = entries
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func sampleSSH() []logs.Entry {
	now := time.Now().UnixMilli()
	return []logs.Entry{
		{Time: now - 3_600_000, Message: "Accepted publickey for root from 192.0.2.44 port 51514 ssh2: ED25519 SHA256:abc"},
		{Time: now - 1_800_000, Message: "Invalid user admin from 198.51.100.7 port 40022"},
		{Time: now - 1_700_000, Message: "Failed password for root from 198.51.100.7 port 40030 ssh2"},
	}
}
