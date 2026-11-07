package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"godebplay/plugins/wireguard"
)

// runTrust handles `godeb-play trust enable|disable|show`, the CLI side of the
// trusted endpoint card in the web UI (same wireguard.SetTrust).
func runTrust(args []string, stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "godeb-play trust muss als root laufen: sudo godeb-play trust …")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "enable":
		fs := flag.NewFlagSet("trust enable", flag.ContinueOnError)
		fs.SetOutput(stderr)
		address := fs.String("address", "", "LAN-Adresse dieses Servers (Standard: Adresse der Default-Route)")
		port := fs.Int("port", 8787, "TCP-Port im Heimnetz")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := enableTrust(ctx, *address, *port, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "disable":
		if _, err := wireguard.SetTrust(ctx, false, "", 0); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "Trusted Endpoint abgeschaltet. Die App hält den Tunnel jetzt auch zu Hause offen.")
		return 0
	case "show":
		info := wireguard.LocalTrust()
		if !info.Enabled {
			fmt.Fprintln(stdout, "Trusted Endpoint ist aus. Einschalten: godeb-play trust enable")
			return 0
		}
		fmt.Fprintf(stdout, "URL:  %s\nKey:  %s\n", info.URL, info.Key)
		return 0
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func enableTrust(ctx context.Context, address string, port int, out io.Writer) error {
	cfg, err := wireguard.SetTrust(ctx, true, address, port)
	var reqErr *wireguard.RequestError
	if errors.As(err, &reqErr) {
		return errors.New(reqErr.Msg)
	}
	if err != nil {
		return err
	}
	info := wireguard.LocalTrust()
	fmt.Fprintf(out, "  Trusted Endpoint: %s (nur aus %s über %s erreichbar)\n", info.URL, cfg.Prefix, cfg.Iface)
	if wireguard.WaitTrustListening(12 * time.Second) {
		fmt.Fprintln(out, "  Der GoDeb-Dienst beantwortet ihn.")
	} else {
		fmt.Fprintln(out, "  Der GoDeb-Dienst antwortet noch nicht: systemctl status godeb, journalctl -u godeb -e")
	}
	fmt.Fprintln(out, "  Neue Handy-Konfigurationen vom Hub enthalten ihn automatisch; vorhandene auf dem Hub mit")
	fmt.Fprintln(out, "  `godeb site sync` aktualisieren und den QR-Code neu scannen.")
	return nil
}
