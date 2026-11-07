package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"godebplay/backend/firstrun"
	"godebplay/plugins/ufw"
)

// runAccess is `godeb-play access`: the temporary remote access, the same
// functions as the switch on the firewall page.
func runAccess(args []string, stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "godeb-play access muss als root laufen: sudo godeb-play access …")
		return 1
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	switch args[0] {
	case "open":
		fs := flag.NewFlagSet("access open", flag.ContinueOnError)
		fs.SetOutput(stderr)
		d := fs.Duration("for", ufw.RemoteDefault, "Dauer, z. B. 30m oder 2h (höchstens 24h)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		r, err := ufw.OpenRemote(ctx, *d)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "Fernzugang offen bis %s:\n  %s\n", r.Until.Local().Format("02.01.2006 15:04"), r.URL)
		// The web process creates the certificate when it opens the port.
		for range 10 {
			if fp, err := firstrun.CertFingerprint(); err == nil {
				fmt.Fprintf(stdout, "Zertifikat (selbstsigniert), SHA-256:\n  %s\n", fp)
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		fmt.Fprintln(stdout, "Anmeldung mit Passwort und 2FA wie im Tunnel. Schließen: sudo godeb-play access close")
		fmt.Fprintln(stdout, "Nutzt du die Hetzner Cloud Firewall, dort Port 8443/tcp ebenfalls freigeben.")
		return 0
	case "close":
		if err := ufw.CloseRemote(ctx); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "Fernzugang geschlossen.")
		return 0
	case "status":
		r, err := ufw.RemoteStatus(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if !r.Open {
			fmt.Fprintln(stdout, "Fernzugang geschlossen.")
			return 0
		}
		fmt.Fprintf(stdout, "Fernzugang offen bis %s: %s\n", r.Until.Local().Format("02.01.2006 15:04"), r.URL)
		return 0
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}
