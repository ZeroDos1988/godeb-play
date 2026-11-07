// Package logs shows GoDeb's own journal: the web process and the root
// agent, with level, time range and text filters. It only ever reads the two
// GoDeb units; other services have their own views.
package logs

import (
	"net/http"
	"strconv"
	"strings"

	"godebplay/backend/core"
)

func init() {
	core.Register("logs", Mount)
}

// Mount registers the log routes.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/logs/entries", handleEntries)
}

// sources maps the UI choice to the units passed to journalctl.
var sources = map[string][]string{
	"all":   {"godeb-play.service", "godeb-play-agent.service"},
	"web":   {"godeb-play.service"},
	"agent": {"godeb-play-agent.service"},
}

// levels maps the UI choice to journalctl -p (this level and worse).
var levels = map[string]string{
	"error":   "err",
	"warning": "warning",
	"info":    "info",
	"debug":   "debug",
}

// ranges maps the UI choice to a relative journalctl --since.
var ranges = map[string]string{
	"15m": "-15min",
	"1h":  "-1h",
	"24h": "-24h",
	"7d":  "-7d",
}

const (
	defaultLines = 200
	maxLines     = 1000
	maxQuery     = 100
)

// Query is a validated filter.
type Query struct {
	Units []string
	Level string // journalctl priority name
	Since string // journalctl relative time, "" for no limit
	Lines int
	Text  string // case-insensitive substring, applied after reading
}

// ParseQuery reads the filter from URL values. Every value is checked
// against a fixed list; unknown values fall back to the default.
func ParseQuery(get func(string) string) (Query, bool) {
	q := Query{Units: sources["all"], Level: levels["info"], Since: ranges["24h"], Lines: defaultLines}
	if v := get("source"); v != "" {
		units, ok := sources[v]
		if !ok {
			return q, false
		}
		q.Units = units
	}
	if v := get("level"); v != "" {
		l, ok := levels[v]
		if !ok {
			return q, false
		}
		q.Level = l
	}
	if v := get("since"); v != "" {
		s, ok := ranges[v]
		if !ok && v != "all" {
			return q, false
		}
		q.Since = s
	}
	if v := get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return q, false
		}
		q.Lines = min(n, maxLines)
	}
	q.Text = strings.TrimSpace(get("q"))
	if len(q.Text) > maxQuery {
		return q, false
	}
	return q, true
}

// Args builds the journalctl argument list.
func (q Query) Args() []string {
	args := []string{"--no-pager", "--quiet", "--output=json", "--priority=" + q.Level}
	for _, u := range q.Units {
		args = append(args, "--unit="+u)
	}
	if q.Since != "" {
		args = append(args, "--since="+q.Since)
	}
	// With a text filter read more lines, the filter runs afterwards.
	lines := q.Lines
	if q.Text != "" {
		lines = maxLines * 5
	}
	return append(args, "--lines="+strconv.Itoa(lines))
}

type entriesResponse struct {
	core.CommandEnvelope
	Entries []Entry `json:"entries"`
}

func handleEntries(w http.ResponseWriter, r *http.Request) {
	q, ok := ParseQuery(r.URL.Query().Get)
	if !ok {
		core.WriteError(w, http.StatusBadRequest, "Ungültiger Filter")
		return
	}
	out, env := core.ReadCommand(r.Context(), sampleJournal, "journalctl", q.Args()...)
	entries := Filter(MergeForwarded(ParseJournal(out)), q.Text, q.Lines)
	core.WriteJSON(w, http.StatusOK, entriesResponse{CommandEnvelope: env, Entries: entries})
}
