package core

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"godebplay/backend/logging"
)

// CommandResult is the raw outcome of a native OS command.
type CommandResult struct {
	Command []string
	Stdout  string
	Stderr  string
	Err     error
}

// Run executes a command without a shell. Locale is pinned to C so parsers
// see the English Debian command output.
func Run(ctx context.Context, name string, args ...string) CommandResult {
	return RunInput(ctx, "", name, args...)
}

// RunInput is Run with stdin. Secrets such as private keys are passed this
// way so they never appear in the process list.
func RunInput(ctx context.Context, stdin, name string, args ...string) CommandResult {
	return run(ctx, 30*time.Second, stdin, slog.LevelWarn, name, args...)
}

// RunQuiet is Run for status probes whose non-zero exit is an answer, not
// an error (systemctl is-active of a stopped unit): failures log at debug.
func RunQuiet(ctx context.Context, name string, args ...string) CommandResult {
	return run(ctx, 30*time.Second, "", slog.LevelDebug, name, args...)
}

// RunTimeout is Run with an explicit deadline. Package installs and SteamCMD
// exceed the 30 second default.
func RunTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) CommandResult {
	return run(ctx, timeout, "", slog.LevelWarn, name, args...)
}

// RunAdminTimeout is RunAdmin with an explicit deadline.
func RunAdminTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) CommandResult {
	if os.Geteuid() == 0 {
		return RunTimeout(ctx, timeout, name, args...)
	}
	sudoArgs := append([]string{"-n", "--", name}, args...)
	return RunTimeout(ctx, timeout, "sudo", sudoArgs...)
}

// run executes the command and logs it: successes at debug, failures at
// failLevel. Arguments are logged, stdin never (secrets go there).
func run(ctx context.Context, timeout time.Duration, stdin string, failLevel slog.Level, name string, args ...string) CommandResult {
	if ctx == nil {
		ctx = context.Background()
	}
	logCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(),
		"LC_ALL=C",
		"LANG=C",
		"DEBIAN_FRONTEND=noninteractive",
		// Files Debian manages with ucf (dovecot.conf) keep GoDeb's
		// version on package updates instead of asking.
		"UCF_FORCE_CONFFOLD=1",
	)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	res := CommandResult{
		Command: append([]string{name}, args...),
		Stdout:  stdout.String(),
		Stderr:  stderr.String(),
		Err:     err,
	}
	logCommand(logCtx, res, time.Since(start), failLevel)
	return res
}

func logCommand(ctx context.Context, res CommandResult, took time.Duration, failLevel slog.Level) {
	level, msg := slog.LevelDebug, "Befehl ausgeführt"
	if res.Err != nil {
		level, msg = failLevel, "Befehl fehlgeschlagen"
	}
	if !slog.Default().Enabled(ctx, level) {
		return
	}
	attrs := []slog.Attr{
		slog.Any("befehl", res.Command),
		slog.Int("exit", exitCode(res.Err)),
		slog.Duration("dauer", took.Round(time.Millisecond)),
	}
	if u := logging.User(ctx); u != "" {
		attrs = append(attrs, slog.String("benutzer", u))
	}
	if res.Err != nil {
		attrs = append(attrs, slog.String("fehler", logging.Truncate(res.Detail(), 400)))
	}
	slog.LogAttrs(ctx, level, msg, attrs...)
}

// exitCode is the process exit status, 0 on success and -1 when the
// command did not run or was killed.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// RunAdmin executes a command as root. The current process is used when it
// already is root; otherwise the command is passed to sudo -n.
func RunAdmin(ctx context.Context, name string, args ...string) CommandResult {
	return RunAdminInput(ctx, "", name, args...)
}

// RunAdminQuiet is RunAdmin for probes whose failure is an answer, not an
// error (e.g. "nft list table" of a table that does not exist yet): a
// failure only logs at debug, so the journal holds no false warnings.
func RunAdminQuiet(ctx context.Context, name string, args ...string) CommandResult {
	if os.Geteuid() == 0 {
		return RunQuiet(ctx, name, args...)
	}
	return RunQuiet(ctx, "sudo", append([]string{"-n", "--", name}, args...)...)
}

// RunAdminInput is RunAdmin with stdin.
func RunAdminInput(ctx context.Context, stdin, name string, args ...string) CommandResult {
	if os.Geteuid() == 0 {
		return RunInput(ctx, stdin, name, args...)
	}
	sudoArgs := append([]string{"-n", "--", name}, args...)
	return RunInput(ctx, stdin, "sudo", sudoArgs...)
}

// Detail returns stderr, or the exec error when stderr is empty.
func (r CommandResult) Detail() string {
	msg := strings.TrimSpace(r.Stderr)
	if msg == "" && r.Err != nil {
		msg = r.Err.Error()
	}
	return msg
}

// CommandEnvelope is the JSON view of a command shared by every plugin.
type CommandEnvelope struct {
	Command []string `json:"command"`
	Mocked  bool     `json:"mocked"`
	Detail  string   `json:"detail,omitempty"`
}

// ReadCommand runs a read-only OS command. If it fails, stdout is replaced
// with the supplied Debian sample so the same parser still produces a payload.
// Failures only log at debug: a missing tool is expected and polled often.
func ReadCommand(ctx context.Context, mockStdout, name string, args ...string) (string, CommandEnvelope) {
	res := run(ctx, 30*time.Second, "", slog.LevelDebug, name, args...)
	env := CommandEnvelope{Command: res.Command}
	if res.Err != nil {
		env.Mocked = true
		env.Detail = res.Detail()
		return mockStdout, env
	}
	return res.Stdout, env
}
