package core

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"godebplay/backend/logging"
)

func TestRunLogsCommands(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(logging.New(&buf, "test", slog.LevelDebug, true))
	defer slog.SetDefault(old)

	ctx := logging.WithUser(context.Background(), "admin")
	RunInput(ctx, "geheim", "sh", "-c", "cat >/dev/null; echo kaputt >&2; exit 3")
	Run(ctx, "true")
	ReadCommand(ctx, "", "false")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %q", lines)
	}
	if !strings.HasPrefix(lines[0], `<4>level=WARN msg="Befehl fehlgeschlagen"`) ||
		!strings.Contains(lines[0], "exit=3") || !strings.Contains(lines[0], "benutzer=admin") ||
		!strings.Contains(lines[0], "fehler=kaputt") {
		t.Fatalf("failure line = %q", lines[0])
	}
	if strings.Contains(buf.String(), "geheim") {
		t.Fatal("stdin must never be logged")
	}
	if !strings.HasPrefix(lines[1], `<7>level=DEBUG msg="Befehl ausgeführt"`) {
		t.Fatalf("success line = %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], `<7>level=DEBUG msg="Befehl fehlgeschlagen"`) {
		t.Fatalf("read failures stay at debug: %q", lines[2])
	}
}
