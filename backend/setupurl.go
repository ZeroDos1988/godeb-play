package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"godebplay/backend/core"
	"godebplay/backend/firstrun"
)

// runSetupURL prints the link to the web wizard with the one-time token and
// the certificate fingerprint. Only root can read the token.
func runSetupURL(stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "godeb-play setup-url muss als root laufen: sudo godeb-play setup-url")
		return 1
	}
	// Never hand out a token for a server configured before the wizard.
	firstrun.Migrate()
	if !firstrun.Required() {
		fmt.Fprintln(stdout, "Die Ersteinrichtung ist abgeschlossen.")
		firstrun.WriteSummary(stdout, firstrun.BuildSummary(context.Background()))
		return 0
	}
	tok, err := firstrun.EnsureToken()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	_, fp, err := firstrun.EnsureCert()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	port := strconv.Itoa(firstrun.SetupPort())
	seen := map[string]bool{}
	var urls []string
	hosts := []string{core.DefaultRoute(context.Background()).Src}
	for _, a := range core.LANAddresses() {
		hosts = append(hosts, a.Address)
	}
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		urls = append(urls, fmt.Sprintf("https://%s/#/setup?token=%s", net.JoinHostPort(h, port), tok))
	}
	line := strings.Repeat("=", 66)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, line)
	fmt.Fprintln(stdout, "  GoDeb ist installiert. Jetzt die Einrichtung im Browser öffnen:")
	fmt.Fprintln(stdout)
	for i, u := range urls {
		if i == 1 {
			fmt.Fprintln(stdout, "  oder über eine andere Adresse dieses Servers:")
		}
		fmt.Fprintf(stdout, "    -> %s\n", u)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  Der Browser warnt beim ersten Aufruf (selbstsigniertes Zertifikat).")
	fmt.Fprintln(stdout, "  In den Zertifikatsdetails diesen SHA-256-Fingerprint vergleichen:")
	fmt.Fprintf(stdout, "    %s\n", fp)
	if st := core.RunAdmin(context.Background(), "ufw", "status"); st.Err == nil && strings.Contains(st.Stdout, "Status: active") {
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "  ufw ist aktiv. Vorher freigeben: sudo ufw allow %s/tcp\n", port)
		fmt.Fprintln(stdout, "  (der Assistent entfernt die Regel am Ende wieder)")
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  Link später erneut anzeigen: sudo godeb-play setup-url   Ohne Browser: sudo godeb-play setup")
	fmt.Fprintln(stdout, line)
	fmt.Fprintln(stdout)
	return 0
}

// runSummary prints how this server is set up and how to reach it.
func runSummary(stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "godeb-play summary muss als root laufen: sudo godeb-play summary")
		return 1
	}
	firstrun.WriteSummary(stdout, firstrun.BuildSummary(context.Background()))
	return 0
}
