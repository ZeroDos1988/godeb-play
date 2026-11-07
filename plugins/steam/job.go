package steam

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const maxLogLines = 400

// Job is the state of the one long-running action (install or update). Only
// one runs at a time across all games: parallel SteamCMD downloads would just
// compete for the same line and disk.
type Job struct {
	Game     string   `json:"game"`
	Action   string   `json:"action"`
	Step     string   `json:"step"`
	Running  bool     `json:"running"`
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	Started  string   `json:"started"`
	Finished string   `json:"finished,omitempty"`
	Log      []string `json:"log"`
}

type jobRunner struct {
	mu  sync.Mutex
	job *Job
}

var jobs jobRunner

// snapshot returns a copy of the current job of game, or nil.
func (r *jobRunner) snapshot(game string) *Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.job == nil || r.job.Game != game {
		return nil
	}
	cp := *r.job
	cp.Log = append([]string(nil), r.job.Log...)
	return &cp
}

// start runs fn in the background unless another job is running. The job
// outlives the HTTP request; it ends when fn returns or the daemon stops.
func (r *jobRunner) start(game, action string, fn func(ctx context.Context, j *jobHandle) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.job != nil && r.job.Running {
		return fmt.Errorf("%s für %s läuft bereits", r.job.Action, r.job.Game)
	}
	r.job = &Job{Game: game, Action: action, Running: true, Started: time.Now().UTC().Format(time.RFC3339), Log: []string{}}
	h := &jobHandle{r: r}
	started := time.Now()
	jobEvent(game, action, started, nil, false)
	slog.Info("Spielserver-Job gestartet", "spiel", game, "aktion", action)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		err := fn(ctx, h)
		jobEvent(game, action, started, err, true)
		r.mu.Lock()
		defer r.mu.Unlock()
		logJobEnd("Spielserver-Job", err, started, r.job.Log, "spiel", game, "aktion", action)
		r.job.Running = false
		r.job.Finished = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			r.job.Error = err.Error()
			r.job.Log = appendLog(r.job.Log, "FEHLER: "+err.Error())
		} else {
			r.job.OK = true
			r.job.Step = "Fertig"
		}
	}()
	return nil
}

type jobHandle struct {
	r *jobRunner
}

func (h *jobHandle) step(name string) {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	h.r.job.Step = name
	h.r.job.Log = appendLog(h.r.job.Log, "==> "+name)
}

func (h *jobHandle) logf(format string, args ...any) {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	h.r.job.Log = appendLog(h.r.job.Log, fmt.Sprintf(format, args...))
}

// run executes a command without a shell and streams its output into the
// job log. SteamCMD redraws progress with \r, so both \r and \n split lines.
func (h *jobHandle) run(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive")
	cmd.Env = append(cmd.Env, env...)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	h.logf("$ %s %s", name, strings.Join(args, " "))
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		sc.Split(splitLines)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				h.logf("%s", line)
			}
		}
	}()
	err := cmd.Run()
	pw.Close()
	<-done
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s: Zeitlimit %s überschritten", name, timeout)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func splitLines(data []byte, atEOF bool) (int, []byte, error) {
	for i, b := range data {
		if b == '\n' || b == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func appendLog(lines []string, line string) []string {
	lines = append(lines, line)
	if len(lines) > maxLogLines {
		lines = lines[len(lines)-maxLogLines:]
	}
	return lines
}

// logJobEnd writes the outcome of a background job to the journal. The job
// log in the UI is lost on restart; on failure the last lines go along, so
// the journal alone explains what went wrong.
func logJobEnd(what string, err error, started time.Time, log []string, attrs ...any) {
	attrs = append(attrs, "dauer", time.Since(started).Round(time.Second))
	if err == nil {
		slog.Info(what+" fertig", attrs...)
		return
	}
	tail := log
	if len(tail) > 8 {
		tail = tail[len(tail)-8:]
	}
	attrs = append(attrs, "fehler", err.Error(), "letzte_zeilen", strings.Join(tail, " | "))
	slog.Error(what+" fehlgeschlagen", attrs...)
}
