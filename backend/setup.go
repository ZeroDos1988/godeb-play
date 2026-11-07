package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"godebplay/backend/auth"
	"godebplay/backend/core"
	"godebplay/backend/firstrun"
	"godebplay/plugins/wireguard"
)

// setupOptions are the answers of `godeb-play setup`. Every value has a flag so
// the command also runs unattended (--yes).
type setupOptions struct {
	Admin    string
	Address  string
	Port     int
	UIPort   int
	Endpoint string
	Client   string
	SSHPort  int
	NoUFW    bool
	Join     string
	Role     string
	Access   string
	LAN      string
	Yes      bool
}

// runSetup performs the first-run setup: admin account, wg0, firewall and a
// first client. The client goes through wireguard.CreatePeer, the same code
// the web UI uses, so it shows up there with its QR code.
func runSetup(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opt setupOptions
	fs.StringVar(&opt.Admin, "admin", "admin", "lokaler Administrator")
	fs.IntVar(&opt.UIPort, "ui-port", 8080, "Port der Web-UI im Tunnel")
	fs.IntVar(&opt.SSHPort, "ssh-port", 0, "SSH-Port, der in ufw offen bleibt (0 = erkennen)")
	fs.StringVar(&opt.Join, "join", "", "Client-Datei oder Beitrittscode eines GoDeb-Hubs (- liest von stdin)")
	fs.StringVar(&opt.Role, "role", "", "peer (an einen GoDeb-Hub anbinden, mit --join) oder none (ohne WireGuard, nur zum Ausprobieren)")
	fs.StringVar(&opt.Access, "access", "", "Erreichbarkeit der Web-UI: tunnel, lan (HTTPS im Heimnetz) oder local")
	fs.StringVar(&opt.LAN, "lan-address", "", "LAN-Adresse für --access lan (Standard: Adresse der Default-Route)")
	fs.BoolVar(&opt.NoUFW, "no-firewall", false, "ufw nicht aktivieren, nur Regeln anlegen")
	fs.BoolVar(&opt.Yes, "yes", false, "keine Rückfragen, Standardwerte nehmen")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "godeb-play setup muss als root laufen: sudo godeb-play setup")
		return 1
	}
	in := bufio.NewReader(stdin)
	// Installing the mail gateway packages can take a while on a fresh VPS.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	s := setup{opt: opt, in: in, out: stdout, stdin: stdin, stderr: stderr}
	if err := s.run(ctx); err != nil {
		fmt.Fprintf(stderr, "\nEinrichtung abgebrochen: %v\n", err)
		return 1
	}
	return 0
}

type setup struct {
	opt    setupOptions
	steps  int
	peer   wireguard.RoleInfo // set when this host is (or becomes) a peer of a hub
	in     *bufio.Reader
	stdin  io.Reader
	out    io.Writer
	stderr io.Writer
}

func (s *setup) step(n int, title string) {
	fmt.Fprintf(s.out, "\n[%d/%d] %s\n", n, s.steps, title)
}

func (s *setup) run(ctx context.Context) error {
	if !firstrun.Required() {
		fmt.Fprintln(s.out, "Hinweis: Die Ersteinrichtung ist bereits abgeschlossen; vorhandene Einstellungen bleiben, fehlende werden ergänzt.")
	}
	role, err := wireguard.CurrentRole()
	if err != nil {
		return err
	}
	if role.Role == wireguard.RolePeer {
		s.peer = role
	}
	switch {
	case s.opt.Join != "" || s.peer.Role == wireguard.RolePeer:
		s.opt.Role = "peer"
	case role.Role == wireguard.RoleHub:
		return errors.New("Dieser Server ist ein WireGuard-Hub. GoDeb Play hängt sich nur als Standort an einen Hub; den Hub verwaltet GoDeb")
	case s.opt.Role == "" && s.opt.Yes:
		return errors.New("--role peer (mit --join) oder none angeben")
	case s.opt.Role == "":
		s.opt.Role = s.ask("Rolle: peer (an einen GoDeb-Hub anbinden) oder none (ohne WireGuard)", "peer")
	}
	switch s.opt.Role {
	case "peer":
		if s.opt.Join == "" && s.peer.Role != wireguard.RolePeer {
			s.opt.Join = s.ask("Beitrittscode (- zum Einfügen) oder Pfad zur Client-Datei des Hubs", "-")
		}
		return s.runPeer(ctx)
	case "none":
		return s.runNone(ctx)
	default:
		return fmt.Errorf("unbekannte Rolle %q", s.opt.Role)
	}
}

// runNone sets up GoDeb without WireGuard: admin, firewall and access from
// the home network (HTTPS) or locally only.
func (s *setup) runNone(ctx context.Context) error {
	s.steps = 2
	fmt.Fprintln(s.out, "GoDeb Ersteinrichtung ohne WireGuard: Administrator, Firewall und Erreichbarkeit.")
	s.step(1, "Administrator")
	if err := s.admin(); err != nil {
		return err
	}
	s.step(2, "Firewall und Erreichbarkeit")
	if err := s.firewall(ctx, firstrun.AccessLAN); err != nil {
		return err
	}
	fmt.Fprintln(s.out, "\nFertig.")
	return nil
}

// runPeer sets up a host behind a GoDeb hub (the home VM): admin, wg0 from
// the hub's client file, firewall. Clients are created on the hub.
func (s *setup) runPeer(ctx context.Context) error {
	s.steps = 4
	fmt.Fprintln(s.out, "GoDeb Ersteinrichtung als Peer eines Hubs: Administrator, Tunnel zum Hub, Firewall, Trusted Endpoint.")
	fmt.Fprintln(s.out, "Danach ist die Web-UI nur über den Tunnel und lokal erreichbar.")

	s.step(1, "Administrator")
	if err := s.admin(); err != nil {
		return err
	}

	s.step(2, "Tunnel zum Hub (wg0)")
	if err := s.join(ctx); err != nil {
		return err
	}

	s.step(3, "Trusted Endpoint im Heimnetz")
	s.trust(ctx)

	s.step(4, "Firewall und Erreichbarkeit")
	if err := s.firewall(ctx, firstrun.AccessLAN); err != nil {
		return err
	}

	fmt.Fprintf(s.out, "\nFertig. Web-UI dieses Servers: http://%s:%d\n", s.peer.Address, s.opt.UIPort)
	fmt.Fprintln(s.out, "Vom Handy aus über den Hub erreichbar, wenn der Peer dort als Standort angelegt ist (godeb site add).")
	return nil
}

// join writes wg0.conf from --join through wireguard.JoinHub, the same code
// as "Mit Hub verbinden" in the web UI, and starts the tunnel.
func (s *setup) join(ctx context.Context) error {
	if s.opt.Join == "" {
		fmt.Fprintf(s.out, "  %s ist bereits Peer des Hubs %s (Adresse %s), wird nicht verändert.\n",
			wireguard.ConfigPath(), s.peer.Hub, s.peer.Address)
	} else {
		content, err := s.joinInput()
		if err != nil {
			return err
		}
		res, err := wireguard.JoinHub(ctx, content)
		if err != nil {
			return err
		}
		for _, note := range res.Notes {
			fmt.Fprintf(s.out, "  Hinweis: %s\n", note)
		}
		fmt.Fprintf(s.out, "  %s geschrieben: Adresse %s, Hub %s\n", wireguard.ConfigPath(), res.Address, res.Hub)
		if s.opt.Join != "-" {
			fmt.Fprintf(s.out, "  Die Client-Datei %s enthält den privaten Schlüssel; danach löschen.\n", s.opt.Join)
		}
		s.peer = wireguard.RoleInfo{Role: wireguard.RolePeer, Hub: res.Hub, Address: res.Address}
	}
	if err := s.enableTunnel(ctx); err != nil {
		return err
	}
	if wireguard.WaitHandshake(ctx, 15*time.Second) {
		fmt.Fprintln(s.out, "  Handshake mit dem Hub steht.")
	} else {
		fmt.Fprintln(s.out, "  Noch kein Handshake mit dem Hub. Prüfen: Port 51820/udp am Hub offen, Peer dort angelegt, `wg show` auf beiden Seiten.")
	}
	return nil
}

// joinInput reads the client file or join code from --join; "-" reads a
// pasted join code (or file) from stdin up to an empty line or EOF.
func (s *setup) joinInput() (string, error) {
	if s.opt.Join == "-" {
		fmt.Fprintln(s.out, "  Beitrittscode einfügen und Enter drücken (eine Client-Datei mit Strg+D abschließen):")
		var b strings.Builder
		for b.Len() <= 64<<10 {
			line, err := s.in.ReadString('\n')
			blank := strings.TrimSpace(line) == ""
			// A code ends at the first empty line; a file has empty lines
			// between its sections and ends at EOF.
			code := strings.HasPrefix(strings.ToLower(strings.TrimSpace(b.String())), wireguard.JoinCodePrefix)
			if blank && code {
				break
			}
			b.WriteString(line)
			if err != nil || wireguard.CompleteJoinCode(b.String()) {
				break
			}
		}
		if strings.TrimSpace(b.String()) == "" {
			return "", errors.New("nichts eingefügt")
		}
		return b.String(), nil
	}
	info, err := os.Stat(s.opt.Join)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return "", fmt.Errorf("%s ist keine Client-Datei", s.opt.Join)
	}
	content, err := os.ReadFile(s.opt.Join)
	return string(content), err
}

// trust offers the signed trusted endpoint on the LAN address, so the GoDeb
// WireGuard app switches the tunnel off at home. Same function as the UI.
func (s *setup) trust(ctx context.Context) {
	if info := wireguard.LocalTrust(); info.Enabled {
		fmt.Fprintf(s.out, "  Läuft bereits: %s\n", info.URL)
		return
	}
	lan := detectHost()
	if lan == "" {
		fmt.Fprintln(s.out, "  Keine LAN-Adresse erkannt. Später: godeb-play trust enable --address <lan-ip>")
		return
	}
	if !s.confirm(fmt.Sprintf("Trusted Endpoint auf %s:8787 anbieten (Handy schaltet den Tunnel im Heim-WLAN ab)?", lan)) {
		fmt.Fprintln(s.out, "  Übersprungen. Später: godeb-play trust enable")
		return
	}
	if err := enableTrust(ctx, lan, 8787, s.out); err != nil {
		fmt.Fprintf(s.out, "  Nicht eingerichtet: %v\n", err)
	}
}

func (s *setup) admin() error {
	exists, err := auth.UserExists(s.opt.Admin)
	if err != nil {
		return err
	}
	if exists {
		fmt.Fprintf(s.out, "  %s existiert bereits, Passwort bleibt.\n", s.opt.Admin)
		return nil
	}
	if s.opt.Yes {
		return fmt.Errorf("Benutzer %s fehlt; zuerst `godeb-play user passwd %s` oder ohne --yes starten", s.opt.Admin, s.opt.Admin)
	}
	fmt.Fprintf(s.out, "  Lege %s an (12 bis 72 Zeichen).\n", s.opt.Admin)
	if code := setPassword(s.opt.Admin, s.stdin, s.out, s.stderr); code != 0 {
		return errors.New("Passwort nicht gesetzt")
	}
	fmt.Fprintln(s.out, "  2FA wird beim ersten Login in der Web-UI eingerichtet.")
	return nil
}

func (s *setup) enableTunnel(ctx context.Context) error {
	if err := wireguard.StartTunnel(ctx); err != nil {
		return fmt.Errorf("wg-quick@wg0 starten: %w", err)
	}
	fmt.Fprintln(s.out, "  wg-quick@wg0 ist aktiv und startet beim Booten.")
	return nil
}

// firewall asks how the web UI is reached, applies the same plan as the web
// wizard (firstrun.ApplyFirewall) and completes the first-run setup.
func (s *setup) firewall(ctx context.Context, defaultAccess string) error {
	mode := s.opt.Access
	if mode == "" {
		mode = s.ask("Web-UI erreichbar über: tunnel (nur WireGuard), lan (HTTPS im Heimnetz) oder local", defaultAccess)
	}
	lan := s.opt.LAN
	if mode == firstrun.AccessLAN && lan == "" {
		lan = s.ask("LAN-Adresse dieses Servers", detectHost())
	}
	access, err := firstrun.ResolveAccess(mode, lan, 0)
	if err != nil {
		return err
	}
	role, _ := wireguard.CurrentRole()
	if access.Mode == firstrun.AccessTunnel && role.Role == wireguard.RoleNone {
		return errors.New("ohne WireGuard gibt es keinen Tunnel; lan oder local wählen")
	}
	plan := firstrun.FirewallPlan{SSHPorts: s.sshPorts(ctx), UIPort: s.opt.UIPort, SetupPort: firstrun.SetupPort()}
	if role.Role == wireguard.RoleHub {
		plan.WireGuard = s.opt.Port
	}
	if role.Role == wireguard.RoleNone {
		plan.UIPort = 0
	}
	if access.Mode == firstrun.AccessLAN {
		plan.LANIface, plan.LANAddress, plan.LANPrefix, plan.LANPort = access.Iface, access.Address, access.Prefix, access.Port
	}
	if !s.opt.NoUFW && len(plan.SSHPorts) > 0 {
		var open []string
		for _, r := range plan.Rules() {
			open = append(open, strings.Join(r[1:len(r)-2], " "))
		}
		plan.Enable = s.confirm("ufw einschalten? Eingehend offen bleibt nur: " + strings.Join(open, "; "))
	}
	lines, err := firstrun.ApplyFirewall(ctx, plan)
	for _, line := range lines {
		fmt.Fprintf(s.out, "  %s\n", line)
	}
	if err != nil {
		return err
	}
	if err := firstrun.SaveAccess(access); err != nil {
		return err
	}
	if access.Mode == firstrun.AccessLAN {
		fmt.Fprintf(s.out, "  Web-UI im Heimnetz: https://%s (selbstsigniertes Zertifikat)\n", access.Addr())
	}
	return firstrun.MarkDone(string(role.Role), access.Mode)
}

// sshPorts returns the SSH ports that must stay reachable: --ssh-port if set,
// otherwise what core.SSHPorts detects.
func (s *setup) sshPorts(ctx context.Context) []int {
	if s.opt.SSHPort > 0 && s.opt.SSHPort <= 65535 {
		return []int{s.opt.SSHPort}
	}
	return core.SSHPorts(ctx)
}

// confirm asks a yes/no question that defaults to yes. With --yes it
// returns true without reading.
func (s *setup) confirm(question string) bool {
	if s.opt.Yes {
		return true
	}
	fmt.Fprintf(s.out, "  %s [J/n]: ", question)
	line, _ := s.in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "j", "ja", "y", "yes":
		return true
	}
	return false
}

// ask prints a question and returns the answer or def. With --yes it
// returns def without reading.
func (s *setup) ask(question, def string) string {
	if s.opt.Yes {
		return def
	}
	if def != "" {
		fmt.Fprintf(s.out, "  %s [%s]: ", question, def)
	} else {
		fmt.Fprintf(s.out, "  %s: ", question)
	}
	line, _ := s.in.ReadString('\n')
	if line = strings.TrimSpace(line); line != "" {
		return line
	}
	return def
}

// detectHost suggests the source address of the default route. On a VPS that
// is the public IP; at home it is the LAN address and needs a DynDNS name.
func detectHost() string {
	return core.DefaultRoute(context.Background()).Src
}
