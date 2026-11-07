package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"godebplay/backend/doctor"
)

// runDoctor prints the read-only health check of this host.
func runDoctor(stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "godeb-play doctor muss als root laufen: sudo godeb-play doctor")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fmt.Fprintf(stdout, "GoDeb Doctor – %s – %s\n\n", hostname(), time.Now().Format("2006-01-02 15:04"))
	if fails, _ := doctor.Write(stdout, doctor.Check(ctx, doctorEnv())); fails > 0 {
		return 1
	}
	return 0
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "?"
	}
	return h
}
