package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"godebplay/plugins/apt"
)

var aptTrigger = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// runAptRun is `godeb-play apt-run check|security|upgrade`, started by the
// agent as godeb-play-apt.service (systemd-run). It also works by hand:
// `sudo godeb-play apt-run security`.
func runAptRun(args []string, stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 && os.Getenv("GODEB_STATE_DIR") == "" {
		fmt.Fprintln(stderr, "godeb-play apt-run muss als root laufen: sudo godeb-play apt-run …")
		return 1
	}
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("apt-run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	trigger := fs.String("trigger", "cli", "wer den Lauf ausgelöst hat (für die Anzeige)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if !aptTrigger.MatchString(*trigger) {
		*trigger = "cli"
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := apt.RunJob(ctx, args[0], *trigger); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "Fertig.")
	return 0
}
