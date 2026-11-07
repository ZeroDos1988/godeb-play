package core

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestReadCommandSuccess(t *testing.T) {
	out, env := ReadCommand(context.Background(), "MOCK", "/bin/echo", "hello")
	if env.Mocked {
		t.Fatalf("unexpected mock: %+v", env)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Fatalf("stdout = %q", out)
	}
	if len(env.Command) != 2 || env.Command[0] != "/bin/echo" || env.Command[1] != "hello" {
		t.Fatalf("command = %#v", env.Command)
	}
}

func TestReadCommandMocksMissingBinary(t *testing.T) {
	out, env := ReadCommand(context.Background(), "MOCK-DATA", "godeb-play-binary-missing", "--flag")
	if !env.Mocked {
		t.Fatal("expected mock")
	}
	if out != "MOCK-DATA" {
		t.Fatalf("stdout = %q", out)
	}
	if env.Detail == "" {
		t.Fatal("expected detail")
	}
	if env.Command[0] != "godeb-play-binary-missing" {
		t.Fatalf("command = %#v", env.Command)
	}
}

func TestRunInputPassesStdin(t *testing.T) {
	res := RunInput(context.Background(), "secret\n", "cat")
	if res.Err != nil || res.Stdout != "secret\n" {
		t.Fatalf("res = %+v", res)
	}
}

func TestRunAdminAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root so sudo is not invoked")
	}
	res := RunAdmin(context.Background(), "/bin/echo", "ok")
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if strings.TrimSpace(res.Stdout) != "ok" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if res.Command[0] != "/bin/echo" {
		t.Fatalf("command = %#v", res.Command)
	}
}
