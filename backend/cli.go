package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"godebplay/backend/auth"
)

const usage = `Aufruf:
  godeb                          Daemon starten (Weboberfläche)
  godeb-play agent [--socket PFAD]    Root-Agent für Systemänderungen (godeb-play-agent.service)
  godeb-play version                  Installierte Version
  godeb-play setup-url                Link zur Ersteinrichtung im Browser (mit Einmal-Token)
  godeb-play summary                  Übersicht: Adressen, Tunnel, Zugang, Firewall
  godeb-play doctor                   Gesundheitscheck (nur lesend, Ausgabe ohne Geheimnisse zum Weitergeben)
  godeb-play setup [--role hub|peer|none] [--access tunnel|lan|local]
                                 Ersteinrichtung ohne Browser: Admin, Rolle, Firewall, Erreichbarkeit
  godeb-play setup --join DATEI       Ersteinrichtung als Peer eines GoDeb-Hubs (Heim-VM hinter dem VPS)
  godeb-play trust enable [--address IP] [--port 8787] | disable | show
                                 Trusted Endpoint im Heimnetz (Auto-Disconnect der App)
  godeb-play access open [--for 2h] | close | status
                                 Fernzugang auf Zeit: HTTPS auf der öffentlichen IP (Port 8443),
                                 schließt sich nach Ablauf von selbst (höchstens 24h)
  godeb-play apt-run check|security|upgrade
                                 Paketlisten prüfen, Sicherheitsupdates oder alle Updates installieren
                                 (läuft sonst automatisch als godeb-play-apt.service)
  godeb-play user passwd <benutzer>   Benutzer anlegen oder Passwort setzen
  godeb-play 2fa reset <benutzer>     2FA zurücksetzen (Notfall, per SSH mit sudo)
  godeb-play sessions revoke <benutzer>  Alle Web-Sitzungen des Benutzers beenden
`

func runCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 1 && (args[0] == "version" || args[0] == "--version"):
		fmt.Fprintln(stdout, version)
		return 0
	case len(args) >= 1 && args[0] == "agent":
		return runAgent(args[1:], stderr)
	case len(args) == 1 && args[0] == "setup-url":
		return runSetupURL(stdout, stderr)
	case len(args) == 1 && args[0] == "summary":
		return runSummary(stdout, stderr)
	case len(args) == 1 && args[0] == "doctor":
		return runDoctor(stdout, stderr)
	case len(args) >= 1 && args[0] == "setup":
		return runSetup(args[1:], stdin, stdout, stderr)
	case len(args) >= 1 && args[0] == "trust":
		return runTrust(args[1:], stdout, stderr)
	case len(args) >= 1 && args[0] == "access":
		return runAccess(args[1:], stdout, stderr)
	case len(args) >= 1 && args[0] == "apt-run":
		return runAptRun(args[1:], stdout, stderr)
	case len(args) == 3 && args[0] == "2fa" && args[1] == "reset":
		return reset2FA(args[2], stdout, stderr)
	case len(args) == 3 && args[0] == "sessions" && args[1] == "revoke":
		return revokeSessions(args[2], stdout, stderr)
	case len(args) == 3 && args[0] == "user" && args[1] == "passwd":
		return setPassword(args[2], stdin, stdout, stderr)
	case len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help"):
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func reset2FA(username string, stdout, stderr io.Writer) int {
	err := auth.Reset2FA(username)
	switch {
	case errors.Is(err, auth.ErrNotEnrolled):
		fmt.Fprintf(stdout, "Für %s ist keine 2FA hinterlegt.\n", username)
		return 0
	case err != nil:
		fmt.Fprintf(stderr, "2FA-Reset fehlgeschlagen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "2FA für %s zurückgesetzt. Beim nächsten Login wird sie neu eingerichtet.\n", username)
	return 0
}

func revokeSessions(username string, stdout, stderr io.Writer) int {
	n, err := auth.RevokeSessions(username, "")
	if err != nil {
		fmt.Fprintf(stderr, "Sitzungen beenden fehlgeschlagen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%d Sitzung(en) von %s beendet.\n", n, username)
	return 0
}

func setPassword(username string, stdin io.Reader, stdout, stderr io.Writer) int {
	if !auth.ValidUsername(username) {
		fmt.Fprintln(stderr, auth.ErrInvalidUsername)
		return 1
	}
	password, err := readPassword(stdin, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "Passwort lesen: %v\n", err)
		return 1
	}
	if err := auth.SetPassword(username, password); err != nil {
		fmt.Fprintf(stderr, "Passwort setzen: %v\n", err)
		return 1
	}
	// Root may allow this account to set up 2FA at its next login; the
	// agent refuses enrollments nobody allowed.
	if err := auth.GrantEnrollment(username); err != nil {
		fmt.Fprintf(stderr, "2FA-Freigabe: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Passwort für %s gespeichert.\n", username)
	return 0
}

// readPassword prompts twice on a terminal and reads one line otherwise.
func readPassword(stdin io.Reader, stderr io.Writer) (string, error) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(stderr, "Neues Passwort: ")
		first, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(stderr, "Wiederholen: ")
		second, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", errors.New("Eingaben stimmen nicht überein")
		}
		return string(first), nil
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
