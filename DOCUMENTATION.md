# GoDeb Play – Dokumentation

GoDeb Play ist ein Spielserver-Panel für einen Container oder eine VM zu Hause. Es tritt einem GoDeb-Hub per WireGuard als Standort bei. Der Unterbau (Weboberfläche, Agent, Anmeldung, Ersteinrichtung) ist aus GoDeb kopiert (Stand `24f6000`, 07.11.2026) und auf einen Standort zugeschnitten.

## Architektur

```text
Browser (Tunnel über den Hub, Heimnetz per HTTPS oder lokal)
   |
   v
godeb-play.service        Benutzer godeb-play, ohne Rechte, ProtectSystem=strict
   |  Login, Sitzungen, 2FA-Abfrage, Oberfläche (/usr/share/godeb-play/frontend/dist)
   |  Daten: /var/lib/godeb-play (godeb.db, master.key, auth/, access.json, tls/)
   |
   |  Unix-Socket /run/godeb-play-agent/agent.sock (0660 root:godeb-play, SO_PEERCRED)
   v
godeb-play-agent.service  root, kein Netz-Listener
      Plugins, privilegierte Setup-Schritte, eigene 2FA-Prüfung
      Daten: /etc/godeb-play (godeb.db, master.key, reboot.json, apt.json)
      Spiele: /var/lib/godeb-play-games/<spiel> (je eigenes Konto), backups/<spiel> (root)
```

| Teil | Ort | Aufgabe |
|---|---|---|
| Weboberfläche | `backend`, `godeb-play` | Anmeldung, Sitzungen, Oberfläche; leitet `/api/plugins/*`, `/api/plugin-manager*` und privilegierte Setup-Schritte an den Agenten |
| Agent | `backend/agent`, `godeb-play agent` | Führt Plugins als root aus und prüft 2FA für jede weitergeleitete Änderung selbst |
| Plugins | `plugins/<id>` | `steam` (Spielserver), `monitor` (Überwachung, Zustand für den Hub), `systemd` (Dienste, Server-Neustart), `ufw` (Firewall), `apt` (Updates), `logs` (Protokoll), `wireguard` (Tunnel zum Hub) |

**Rollen:** Standort eines GoDeb-Hubs (Beitrittscode `godeb-join:…` oder Client-Datei, `wireguard.JoinHub`, dieselbe strenge Prüfung wie in GoDeb: kein `PostUp` und Co., kein Volltunnel) oder ohne WireGuard zum Ausprobieren im Heimnetz. Ein Hub ist GoDeb Play nie; die WireGuard-Seite zeigt nur den Tunnel zum Hub und „Neu beitreten“.

**Erreichbarkeit:** Loopback und `wg0:8080`, nie Klartext-HTTP auf LAN oder WAN. Im Heimnetz nur per HTTPS (Zugangsmodus „Heimnetz“). Der GoDeb-Hub erlaubt Tunnel-Clients den Zugriff auf `<standort>:8080/tcp`, also erreicht das Handy GoDeb Play wie die Heim-VM.

**Nicht übernommen** (gibt es nur in GoDeb): Mail, Domains, Webseiten, PostgreSQL, Cron, Zertifikate, App-Zugang, Portweiterleitung, eigener WireGuard-Server, Volltunnel, Trusted Endpoint (bietet zu Hause schon die Heim-VM an; in GoDeb Play wäre es ein weiterer unauthentifizierter Endpunkt im LAN) und Fernzugang auf Zeit (ein Container zu Hause hat keine öffentliche IP).

### Umgebungsvariablen

Wie in GoDeb (`GODEB_ADDR`, `GODEB_DB`, `GODEB_AGENT_SOCKET`, `GODEB_AGENT_DB`, `GODEB_STATE_DIR`, `GODEB_ROOT`, `GODEB_SETUP_ADDR`, `GODEB_WEB_USER` mit Standard `godeb-play`, …). Neu: `GODEB_STEAM_ROOT` (Spielverzeichnis, Standard `/var/lib/godeb-play-games`; nur für Tests und Entwicklung).

## Installation

### Container unter Proxmox (Vorschlag, noch nicht auf echter Hardware geprüft)

Auf dem Proxmox-Host (Debian-13-Vorlage vorher unter „CT Templates“ laden, ihr genauer Dateiname steht dort bzw. in `pveam list local`; ID, Speicher und Netz anpassen). Enshrouded braucht etwa 8 GB RAM und 30 GB Platte:

```sh
sudo pct create 130 local:vztmpl/<debian-13-vorlage>.tar.zst \
  --hostname spiele --unprivileged 1 --features nesting=1 \
  --cores 4 --memory 12288 --swap 2048 --rootfs local-lvm:40 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp --onboot 1
sudo pct start 130
```

WireGuard läuft im unprivilegierten Container, weil das Modul im Proxmox-Kernel steckt; im Container reicht `wireguard-tools` (kommt als Abhängigkeit des Pakets). Danach das Paket in den Container bringen und installieren:

```sh
sudo pct push 130 godeb-play_<version>_amd64.deb /root/godeb-play.deb
sudo pct exec 130 -- apt install -y --no-install-recommends /root/godeb-play.deb
```

Eine VM mit Debian 13 geht genauso (Paket per `scp` und `sudo apt install ./godeb-play_*.deb`).

### Ersteinrichtung

1. Auf dem GoDeb-Hub einen Standort anlegen: WireGuard → „+ GoDeb-Server zu Hause“ oder `sudo godeb site add spiele`. Der Beitrittscode enthält den privaten Schlüssel des Standorts: nur hier einfügen, nicht per Chat oder Mail weitergeben.
2. Die Installation zeigt den Link zur Einrichtung (Einmal-Token, HTTPS auf Port 8443 mit selbstsigniertem Zertifikat und Fingerabdruck); später erneut mit `sudo godeb-play setup-url`.
3. Im Browser: Administrator, 2FA, „Mit Hub verbinden“ mit dem Beitrittscode, dann Zugang (Tunnel, Heimnetz per HTTPS oder lokal) und Firewall. Der Einrichtungsport schließt sich danach.

Ohne Browser: `sudo godeb-play setup --join -` (Code einfügen) oder `--join DATEI`; `--role none` ohne WireGuard; `--access tunnel|lan|local`, `--lan-address`, `--ui-port`, `--admin`, `--ssh-port`, `--no-firewall`, `--yes`.

## Spielserver (Plugin `steam`)

Spiele sind Beschreibungen im Code (`plugins/steam/<spiel>.go`, `register(&Game{…})`): App-ID, Plattform (Linux oder Windows unter Wine), Startdatei und Argumente, UDP- und TCP-Ports, Konfigurationsdatei mit Vorgabe und Prüfung, Savegame-Verzeichnis (relativ zum Spielverzeichnis, das auch `HOME` ist), optional Bibliotheksverzeichnisse, feste Umgebungsvariablen, Einstellungen für die Kommandozeile und ein Formular (`ui/games/<Spiel>.tsx`). Hinweise pro Spiel stehen als `steam.note.<spiel>` in den Übersetzungen.

| Spiel | App | Plattform | Ports | Einstellungen | Savegames |
|---|---|---|---|---|---|
| Enshrouded | 2278520 | Windows unter Wine | `queryPort` und `queryPort-1` bzw. `gamePort`, UDP | `enshrouded_server.json` (Formular) | `server/savegame` |
| Valheim | 896660 | Linux | 2456–2457/udp (Port wählbar) | Name, Welt, Passwort, öffentlich (Formular) | `.config/unity3d/IronGate/Valheim` |
| Satisfactory | 1690800 | Linux | 7777/udp, 7777/tcp, 8888/tcp | keine; der erste Spieler übernimmt den Server im Spiel | `.config/Epic/FactoryGame/Saved/SaveGames` |

**Einstellungen auf der Kommandozeile** (Valheim): Der Server kennt keine Konfigurationsdatei, nur Argumente. GoDeb Play hält die Werte in `godeb-valheim.json` (Formular und Dateiansicht) und schreibt sie beim Speichern geprüft nach `/etc/godeb-play/games/<spiel>.env` (root, `0600`). Die Unit liest die Datei (`EnvironmentFile=`) und übergibt die Werte als `${NAME}`, jeweils als ein Argument, ohne Shell. Werte dürfen keine Anführungszeichen, Backslashes, `$`, `%`, `;` oder Steuerzeichen enthalten (`renderSettings`, Fuzz-Test `FuzzValheimSettings`). Was das Spielkonto in seiner eigenen JSON-Datei ändert, landet nie auf der Kommandozeile; nur gespeicherte, geprüfte Werte. Grenze: Wie bei jedem Programm mit Passwort-Argument sehen andere lokale Benutzer es per `ps`; im Container sind das nur die Spielkonten.

**Satisfactory:** Der erste Spieler, der sich verbindet, übernimmt den Server und setzt das Admin-Passwort. Direkt nach der Installation über den Tunnel oder im Heimnetz erledigen, bevor der Hub die Ports ins Internet weiterleitet.

**Noch nicht dabei:** Palworld (Einstellungen in einer INI-Datei mit einer sehr langen Zeile `OptionSettings=(…)`; braucht einen eigenen Editor und eine Prüfung statt des JSON-Formulars).

**Installieren** (ein Klick, läuft als Job mit Log): APT-Pakete (`lib32gcc-s1`, bei Windows-Spielen `wine`), Systemkonto `steam-<spiel>`, SteamCMD, Serverdateien (`app_update … validate`, bis zu drei Versuche), Wine-Umgebung, Vorgabe-Konfiguration mit zufälligen Passwörtern, systemd-Unit `godeb-play-<spiel>.service`, Firewall, Start. Serverdateien, die schon im Verzeichnis liegen (z. B. kopiert), übernimmt SteamCMD und prüft sie nur. **Update** stoppt den Server, sichert das Savegame, aktualisiert und startet wieder.

**Firewall:** Als Standort öffnet GoDeb Play die Spielports nur auf `wg0` (`ufw allow in on wg0 … proto udp`). Öffentlich erreichbar werden sie über die Portweiterleitung in GoDeb auf dem Hub (Plugin „Portweiterleitung“, Vorlage Enshrouded, Ziel = Tunnel-Adresse dieses Standorts); die Spielseite nennt Adresse und Ports. Ohne WireGuard öffnet sie nur fürs Heimnetz (`allow from <LAN-Netz>`), nie für alle.

**Savegames:** Vor jedem Update, auf Knopfdruck („Jetzt sichern“, der Server hält dafür kurz an) und vor jeder Wiederherstellung packt der Agent das Savegame-Verzeichnis (bei Enshrouded `saveDirectory`, Standard `./savegame`) nach `/var/lib/godeb-play-games/backups/<spiel>/<zeit>-<anlass>.tar.gz` (root, `0700`). Die letzten zehn bleiben. Wiederherstellen stoppt den Server, sichert den aktuellen Stand, ersetzt das Verzeichnis und startet wieder; Symlinks und Sonderdateien kommen nie in ein Backup und nie aus einem heraus.

**Sicherheit:**

- Jedes Spiel hat ein eigenes Konto; die Unit läuft mit `ProtectSystem=strict`, `ReadWritePaths` nur auf das eigene Verzeichnis, `NoNewPrivileges`, ohne Capabilities, `PrivateTmp`, `PrivateDevices`.
- Der Agent ist root, das Spielverzeichnis gehört dem Spielkonto. Ein übernommener Spielserver könnte dort jederzeit Dateien gegen Symlinks tauschen. Deshalb geht jeder Zugriff des Agenten darin über `os.Root` auf dem Spielverzeichnis (dessen Elternverzeichnis root gehört): Lesen, atomares Schreiben (`writeAtomic`: neue Datei, `Lchown`, `Rename`), `chown` beim Übernehmen von Dateien, Entpacken von SteamCMD und Backups. Tests in `plugins/steam/files_test.go` legen genau solche Symlinks an.
- Installieren, Update und Wiederherstellen verlangen Passwort und frischen Code; Start/Stopp, Konfiguration und „Jetzt sichern“ das 5-Minuten-Fenster.
- Konfigurationen werden vor dem Speichern geprüft (Pfade relativ und im Serververzeichnis, Ports 1024–65535, Größe höchstens 60 KiB); `FuzzValidateEnshrouded` sucht nach Eingaben, die durchrutschen.

**Überwachung:** Spielerzahl und Plätze per Steam-Query (A2S), Traffic der Spielports, Ereignisse (Installation, Update, Start, Backup) auf der Zeitachse. Der GoDeb-Hub holt den Zustand des Standorts samt Spielen über `/api/plugins/monitor/site` ab (ohne Login, nur von der Tunnel-Adresse des Hubs).

## Sicherheitskonzept

Wie in GoDeb: Weboberfläche ohne Rechte, root-Agent mit eigener 2FA-Prüfung (TOTP-Geheimnisse nur in `/etc/godeb-play/godeb.db`, versiegelt mit `/etc/godeb-play/master.key`), frischer Code plus Passwort vor kritischen Aktionen (Firewall, Dienste, Server-Neustart, Plugins, Tunnel, Spiele installieren/aktualisieren/wiederherstellen), Anmeldung in drei Schritten ohne Verraten von Benutzernamen, fail2ban-Jail `godeb-play` (5 Fehlversuche in 10 Minuten), Security-Header, Sitzungen widerrufbar. Öffentlich (ohne Sitzung) sind nur Status, Anmeldung, 2FA, die OIDC-Startpunkte und `monitor/site` (`auth.protected`). Notfallbefehle nur per SSH als root: `godeb-play user passwd`, `godeb-play 2fa reset`, `godeb-play sessions revoke`.

### Server neu starten

Dienste → Karte „Server“, `shutdown -r +1` im Agenten mit Passwort und frischem Code, „Abbrechen“ ohne Code, optional nachts automatisch, wenn `/run/reboot-required` existiert (`/etc/godeb-play/reboot.json`). Spielserver starten danach von selbst (Units sind aktiviert).

### „Beheben“-Knöpfe in der Übersicht

Befunde aus `/api/doctor` können eine Aktion tragen (`fix`), die genau den vorhandenen Endpunkt per POST aufruft, mit derselben 2FA wie auf der Plugin-Seite: Sicherheitsupdates, fehlgeschlagenen Dienst neu starten, Server neu starten, geplanten Neustart abbrechen.

## API

Alle `/api`-Routen außer den oben genannten öffentlichen verlangen eine Sitzung. Zustandsändernde Anfragen brauchen einen 2FA-Code (Fenster 5 Minuten), kritische jedes Mal einen frischen Code plus Passwort (`backend/auth/stepup.go`). `/internal/…` gibt es nur am Agenten-Socket.

| Methode | Pfad | Zweck |
|---|---|---|
| POST | `/api/auth/2fa/authenticate` | TOTP oder Backup-Code |
| POST | `/api/auth/2fa/enroll` | TOTP anlegen |
| POST | `/api/auth/2fa/verify` | Einrichtung bestätigen |
| POST | `/api/auth/identify` | Schritt 1: Benutzername; gleiche Antwort für jeden Namen, unbekannte zählen als Fehlversuch |
| POST | `/api/auth/login` | Passwort, setzt Pending-Cookie |
| POST | `/api/auth/logout` | Sitzung beenden |
| GET | `/api/auth/me` | aktueller Benutzer |
| GET | `/api/auth/oidc/config` | OIDC-Anbieter mit Einstellungen (Admin) |
| GET | `/api/auth/oidc/providers` | öffentliche, fertig konfigurierte Anbieter |
| PUT | `/api/auth/oidc/providers/{id}` | OIDC-Anbieter speichern |
| GET | `/api/auth/oidc/resume` | Pending-Sitzung nach dem Redirect |
| GET | `/api/auth/oidc/{id}/callback` | Rückkehr vom Anbieter |
| GET | `/api/auth/oidc/{id}/start` | Browser-Redirect zum Anbieter |
| GET | `/api/auth/sessions` | eigene Sitzungen mit Gerät, IP, letzter Aktivität |
| POST | `/api/auth/sessions/revoke-others` | alle anderen eigenen Sitzungen beenden |
| POST | `/api/auth/sessions/{id}/revoke` | , `/api/auth/sessions/revoke-others` | eine bzw. alle anderen Sitzungen beenden |
| GET | `/api/doctor` | Server-Diagnose wie `godeb doctor` (nur lesen; mit Agent über `/internal/doctor`, Ausgabe ohne Geheimnisse) |
| GET | `/api/health` | öffentlich, Dienst lebt |
| GET | `/api/plugin-manager` | Plugins mit Paketen, Units, an/aus |
| POST | `/api/plugin-manager/scan` | , `/api/plugin-manager/{id}/install`, `/api/plugin-manager/{id}/enable`, `/api/plugin-manager/{id}/disable` | neu einlesen, Pakete installieren, ein- und ausblenden (frischer 2FA-Code außer bei `scan`) |
| POST | `/api/plugin-manager/{id}/disable` | Plugin abschalten |
| POST | `/api/plugin-manager/{id}/enable` | Plugin einschalten |
| POST | `/api/plugin-manager/{id}/install` | APT-Pakete des Plugins installieren |
| GET | `/api/plugins` | Navigations-Metadaten |
| POST | `/api/plugins/apt/check` | (prüfen; mit Automatik für Sicherheitsupdates wie `security`) |
| POST | `/api/plugins/apt/security` | (prüfen und Sicherheitsupdates installieren) |
| POST | `/api/plugins/apt/settings` | (`autoCheck`, `interval` 5–1440 Minuten, `autoSecurity`) |
| GET | `/api/plugins/apt/upgradable` | (Pakete mit `security`, Automatik, letzter Lauf mit Log) |
| POST | `/api/plugins/apt/upgrade` | (alles aktualisieren, frischer 2FA-Code) |
| GET | `/api/plugins/logs/entries` | Journal-Einträge (Filter nach Dienst und Priorität) |
| GET | `/api/plugins/monitor/access` | Zugriffe: GoDeb-Anmeldungen, SSH, ufw-Blocks |
| GET | `/api/plugins/monitor/alerts` | Alarm-Einstellungen (ntfy, Mail) |
| POST | `/api/plugins/monitor/alerts` | Alarm-Einstellungen speichern |
| POST | `/api/plugins/monitor/alerts/test` | Testalarm senden |
| GET | `/api/plugins/monitor/baseline` | Normalverhalten pro Wochenstunde |
| GET | `/api/plugins/monitor/connections` | Live-Verbindungen (conntrack) |
| GET | `/api/plugins/monitor/events` | Ereignisse auf der Zeitachse |
| GET | `/api/plugins/monitor/series` | Verlauf einer Messreihe |
| GET | `/api/plugins/monitor/site` | (ohne Login, nur von der Tunnel-Adresse des Hubs) |
| GET | `/api/plugins/monitor/summary` | (Ampel, Befunde, aktuelle Werte) |
| GET | `/api/plugins/steam/games` | Spiele mit Zustand |
| POST | `/api/plugins/steam/games/{game}/action` | (`start`, `stop`, `restart`) |
| GET | `/api/plugins/steam/games/{game}/backups` | Savegame-Backups (neueste zuerst, höchstens 10) |
| POST | `/api/plugins/steam/games/{game}/backups` | Backup jetzt; der Server hält kurz an |
| POST | `/api/plugins/steam/games/{game}/backups/{name}/restore` | Backup einspielen; der aktuelle Stand wird vorher gesichert (Passwort und frischer Code) |
| GET | `/api/plugins/steam/games/{game}/config` | Konfigurationsdatei (oder Vorgabe, wenn noch keine existiert) |
| PUT | `/api/plugins/steam/games/{game}/config` | Konfiguration prüfen und speichern, optional neu starten |
| POST | `/api/plugins/steam/games/{game}/install` | Installation als Job: Pakete, Konto, SteamCMD, Server, Unit, Firewall (Passwort und frischer Code) |
| GET | `/api/plugins/steam/games/{game}/job` | laufender oder letzter Job mit Log |
| GET | `/api/plugins/steam/games/{game}/logs` | Journal des Spielservers |
| GET | `/api/plugins/steam/games/{game}/status` | Zustand, Build, Ports, Hub-Hinweis |
| POST | `/api/plugins/steam/games/{game}/update` | Update als Job; vorher Savegame-Backup (Passwort und frischer Code) |
| POST | `/api/plugins/systemd/action` | (`unit`, `action`: `start`, `stop`, `restart`; nicht für GoDebs eigene Units) |
| GET | `/api/plugins/systemd/overview` | (Eckdaten des Servers, ausgewählte Dienste mit Status, Laufzeit, CPU, RAM) |
| GET | `/api/plugins/systemd/reboot` | (Neustart nötig, betroffene Pakete, geplanter Zeitpunkt aus logind, Einstellung des automatischen Neustarts) |
| POST | `/api/plugins/systemd/reboot` | (`shutdown -r +1` mit Ankündigung; Passwort und frischer Code; abgelehnt, solange eine APT-Aktion läuft) |
| POST | `/api/plugins/systemd/reboot/cancel` | (`shutdown -c`; ohne Code, weil es nur einen Neustart verhindert) |
| POST | `/api/plugins/systemd/reboot/settings` | (`auto`, `time` `HH:MM`; `/etc/godeb/reboot.json`) |
| GET | `/api/plugins/systemd/services` | alle Service-Units |
| POST | `/api/plugins/ufw/rules` | Regel anlegen oder löschen |
| GET | `/api/plugins/ufw/status` | Status und Regeln |
| POST | `/api/plugins/wireguard/join` | Hub beitreten (Beitrittscode oder Client-Datei, Passwort und frischer Code) |
| GET | `/api/plugins/wireguard/peers` | Tunnel zum Hub: Rolle, Adresse, Handshake, Traffic |
| GET | `/api/plugins/wireguard/status` | wg0.conf ohne Schlüssel |
| POST | `/api/setup/admin` | ohne Login, mit Header `X-GoDeb-Setup-Token`: erster Administrator |
| POST | `/api/setup/finish` | Erreichbarkeit, Trusted Endpoint, Firewall, Abschluss |
| GET | `/api/setup/info` | öffentliche IP, LAN-Adressen, SSH-Ports, ufw, Zertifikat, `services` (Mail-Gateway installiert, Relay-Domains, Hetzner-Token hinterlegt) |
| POST | `/api/setup/join` | Peer eines Hubs |
| GET | `/api/setup/status` | ohne Login: `required`, `hasAdmin` |
| GET | `/api/setup/summary` | Einrichtungsübersicht |
| GET | `/api/system` | Hostname, OS, Kernel, CPU, RAM, Platte |
| GET | `/api/user/settings` | eigene Sprache und Darstellung |
| POST | `/api/user/settings` | eigene Sprache und Darstellung speichern |
| POST | `/internal/2fa/bind` | Agent: Login-Code an die neue Sitzung binden |
| POST | `/internal/2fa/confirm` | Agent: erste 2FA-Bestätigung |
| POST | `/internal/2fa/enroll` | Agent: 2FA einrichten (nur erstes Konto oder nach Freigabe durch root) |
| GET | `/internal/2fa/status` | Agent: 2FA eingerichtet? |
| POST | `/internal/2fa/validate` | Agent: Code prüfen |
| GET | `/internal/doctor` | Agent: Diagnose (nur lesend) |
| GET | `/internal/plugins/disabled` | Agent: abgeschaltete Plugins |

## Wartung

- **Logs:** `journalctl -u godeb-play -u godeb-play-agent`, je Spiel `journalctl -u godeb-play-<spiel>`; fehlgeschlagene Anmeldungen in `/var/log/godeb-play/auth.log` (für fail2ban).
- **Gesundheit:** `sudo godeb-play doctor` (nur lesend, ohne Geheimnisse), Übersicht der Einrichtung `sudo godeb-play summary`.
- **Updates:** Plugin „Updates“ (APT) wie in GoDeb. Ein APT-Repo für GoDeb Play gibt es noch nicht; neue Versionen kommen als `.deb` aus den Releases.
- **Backups:** Den Container sichert Proxmox. Savegames zusätzlich in GoDeb Play (siehe oben), damit ein kaputtes Update ohne Rückspielen des ganzen Containers zu beheben ist.
- **Entfernen:** `apt purge godeb-play` löscht `/etc/godeb-play`, `/var/lib/godeb-play`, `/var/log/godeb-play` und den Benutzer. Spielserver (Units `godeb-play-<spiel>.service` in `/etc/systemd/system`), Spielkonten und `/var/lib/godeb-play-games` (mit den Backups) bleiben bewusst; `/etc/wireguard/wg0.conf` bleibt.

## Entwicklung

Siehe `CLAUDE.md`. Race-Detector: `go test -race ./...`; Fuzz-Tests: `scripts/fuzz.sh [zeit]`. Ein neues Spiel: `plugins/steam/<spiel>.go` mit `register`, Prüfung der Konfiguration plus Fuzz-Test, optional Formular in `ui/games/` und Eintrag in `ui/games/index.ts`.
