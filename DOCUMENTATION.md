# GoDeb Play – Dokumentation

GoDeb Play ist ein Spielserver-Panel für einen Container oder eine VM zu Hause. Es tritt einem GoDeb-Hub per WireGuard als Standort bei. Der Unterbau (Weboberfläche, Agent, Anmeldung, Ersteinrichtung) ist aus GoDeb kopiert (Stand `24f6000`, 07.11.2026); was dort unter „Architektur“ und „Sicherheitskonzept“ steht, gilt hier genauso, nur mit den Namen unten.

## Architektur

```text
Browser (Tunnel, Heimnetz per HTTPS oder lokal)
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
      Daten: /etc/godeb-play (godeb.db, master.key)
```

| Teil | Ort | Aufgabe |
|---|---|---|
| Weboberfläche | `backend`, `godeb-play` | Anmeldung, Sitzungen, Oberfläche; leitet `/api/plugins/*`, `/api/plugin-manager*` und privilegierte Setup-Schritte an den Agenten |
| Agent | `backend/agent`, `godeb-play agent` | Führt Plugins als root aus und prüft 2FA für jede weitergeleitete Änderung selbst |
| Plugins | `plugins/<id>` | `systemd` (Dienste, Server-Neustart), `ufw` (Firewall), `apt` (Updates), `logs` (Protokoll), `wireguard` (Tunnel zum Hub) |

**Rollen:** Standort eines GoDeb-Hubs (Beitrittscode `godeb-join:…` oder Client-Datei, `wireguard.JoinHub`, dieselbe strenge Prüfung wie in GoDeb: kein `PostUp` und Co., kein Volltunnel) oder ohne WireGuard zum Ausprobieren im Heimnetz. Ein Hub ist GoDeb Play nie.

**Erreichbarkeit:** Loopback und `wg0:8080`, nie Klartext-HTTP auf LAN oder WAN. Im Heimnetz nur per HTTPS (Zugangsmodus „Heimnetz“). Der GoDeb-Hub erlaubt Tunnel-Clients den Zugriff auf `<standort>:8080/tcp`, also erreicht das Handy GoDeb Play wie die Heim-VM.

### Umgebungsvariablen

Wie in GoDeb (`GODEB_ADDR`, `GODEB_DB`, `GODEB_AGENT_SOCKET`, `GODEB_AGENT_DB`, `GODEB_STATE_DIR`, `GODEB_ROOT`, `GODEB_SETUP_ADDR`, `GODEB_WEB_USER` mit Standard `godeb-play`, …). Die Standardpfade zeigen auf `/etc/godeb-play` und `/var/lib/godeb-play`.

## Ersteinrichtung

1. Auf dem GoDeb-Hub einen Standort anlegen: WireGuard → „+ GoDeb-Server zu Hause“ oder `sudo godeb site add spiele`. Der Beitrittscode enthält den privaten Schlüssel des Standorts: nur hier einfügen, nicht per Chat oder Mail weitergeben.
2. GoDeb Play installieren. Die Installation zeigt den Link zur Einrichtung (Einmal-Token, HTTPS auf Port 8443 mit selbstsigniertem Zertifikat und Fingerabdruck); später erneut mit `sudo godeb-play setup-url`.
3. Im Browser: Administrator, 2FA, „Mit Hub verbinden“ mit dem Beitrittscode, dann Zugang (Tunnel, Heimnetz per HTTPS oder lokal) und Firewall. Der Einrichtungsport schließt sich danach.

Ohne Browser: `sudo godeb-play setup --join -` (Code einfügen) oder `--join DATEI`; `--role none` ohne WireGuard; `--access tunnel|lan|local`, `--lan-address`, `--ui-port`, `--admin`, `--ssh-port`, `--no-firewall`, `--yes`.

## Sicherheitskonzept

Unverändert aus GoDeb: Weboberfläche ohne Rechte, root-Agent mit eigener 2FA-Prüfung (TOTP-Geheimnisse nur in `/etc/godeb-play/godeb.db`, versiegelt mit `/etc/godeb-play/master.key`), frischer Code plus Passwort vor kritischen Aktionen (Firewall, Dienste, Server-Neustart, Plugins, Tunnel), Anmeldung in drei Schritten ohne Verraten von Benutzernamen, fail2ban-Jail `godeb-play` (5 Fehlversuche in 10 Minuten), Security-Header, Sitzungen widerrufbar. Notfallbefehle nur per SSH als root: `godeb-play user passwd`, `godeb-play 2fa reset`, `godeb-play sessions revoke`.

Neu für Spielserver (Phase 3): ein Systemkonto und eine Unit pro Spiel, nie root, Ports nur auf `wg0` (optional im LAN).

### Server neu starten

Wie in GoDeb: Dienste → Karte „Server“, `shutdown -r +1` im Agenten mit Passwort und frischem Code, „Abbrechen“ ohne Code, optional nachts automatisch, wenn `/run/reboot-required` existiert (`/etc/godeb-play/reboot.json`).

### „Beheben“-Knöpfe in der Übersicht

Befunde aus `/api/doctor` können eine Aktion tragen (`fix`), die genau den vorhandenen Endpunkt per POST aufruft, mit derselben 2FA wie auf der Plugin-Seite. Heute: Sicherheitsupdates, fehlgeschlagenen Dienst neu starten, Server neu starten, geplanten Neustart abbrechen.

## API

Alle `/api`-Routen außer Status, Login, 2FA und den öffentlichen OIDC-Startpunkten verlangen eine Sitzung. Zustandsändernde Anfragen brauchen einen 2FA-Code (Fenster 5 Minuten), kritische jedes Mal einen frischen Code plus Passwort (`backend/auth/stepup.go`). `/internal/…` gibt es nur am Agenten-Socket.

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/api/auth/me` | aktueller Benutzer |
| GET | `/api/auth/oidc/config` |
| GET | `/api/auth/oidc/providers` | öffentliche, fertig konfigurierte Anbieter |
| GET | `/api/auth/oidc/resume` | Pending-Sitzung nach dem Redirect |
| GET | `/api/auth/oidc/{id}/callback` | Rückkehr vom Anbieter |
| GET | `/api/auth/oidc/{id}/start` | Browser-Redirect zum Anbieter |
| GET | `/api/auth/sessions` | eigene Sitzungen mit Gerät, IP, letzter Aktivität |
| GET | `/api/doctor` | Server-Diagnose wie `godeb doctor` (nur lesen; mit Agent über `/internal/doctor`, Ausgabe ohne Geheimnisse) |
| GET | `/api/health` | öffentlich, Dienst lebt |
| GET | `/api/plugin-manager` | Plugins mit Paketen, Units, an/aus |
| GET | `/api/plugins` | Navigations-Metadaten |
| GET | `/api/plugins/apt/upgradable` (Pakete mit `security`, Automatik, letzter Lauf mit Log) |
| GET | `/api/plugins/demo/ping` |
| GET | `/api/plugins/logs/entries` |
| GET | `/api/plugins/systemd/overview` (Eckdaten des Servers, ausgewählte Dienste mit Status, Laufzeit, CPU, RAM) |
| GET | `/api/plugins/systemd/reboot` (Neustart nötig, betroffene Pakete, geplanter Zeitpunkt aus logind, Einstellung des automatischen Neustarts) |
| GET | `/api/plugins/systemd/services` |
| GET | `/api/plugins/ufw/status` |
| GET | `/api/plugins/wireguard/android`, `/api/plugins/wireguard/android/apk` (GoDeb-Tunnel-App: Infos und Download) |
| GET | `/api/plugins/wireguard/android/apk` |
| GET | `/api/plugins/wireguard/android/token` |
| GET | `/api/plugins/wireguard/peers` |
| GET | `/api/plugins/wireguard/peers/{id}/code` (Beitrittscode eines Standorts) |
| GET | `/api/plugins/wireguard/peers/{id}/config` |
| GET | `/api/plugins/wireguard/peers/{id}/qr` |
| GET | `/api/plugins/wireguard/status` |
| GET | `/api/plugins/wireguard/trust` |
| GET | `/api/plugins/wireguard/trust/info` (ohne Login, für den Hub) |
| GET | `/api/plugins/wireguard/volltunnel` |
| GET | `/api/setup/info` | öffentliche IP, LAN-Adressen, SSH-Ports, ufw, Zertifikat, `services` (Mail-Gateway installiert, Relay-Domains, Hetzner-Token hinterlegt) |
| GET | `/api/setup/status` | ohne Login: `required`, `hasAdmin` |
| GET | `/api/setup/summary` |
| GET | `/api/system` | Hostname, OS, Kernel, CPU, RAM, Platte |
| GET | `/api/user/settings` |
| GET | `/internal/2fa/status` |
| GET | `/internal/doctor` |
| GET | `/internal/plugins/disabled` |
| GET | `/internal/trust/config` |
| POST | `/api/auth/2fa/authenticate` | TOTP oder Backup-Code |
| POST | `/api/auth/2fa/enroll` | TOTP anlegen |
| POST | `/api/auth/2fa/verify` | Einrichtung bestätigen |
| POST | `/api/auth/identify` | Schritt 1: Benutzername; gleiche Antwort für jeden Namen, unbekannte zählen als Fehlversuch |
| POST | `/api/auth/login` | Passwort, setzt Pending-Cookie |
| POST | `/api/auth/logout` | Sitzung beenden |
| POST | `/api/auth/sessions/revoke-others` |
| POST | `/api/auth/sessions/{id}/revoke`, `/api/auth/sessions/revoke-others` | eine bzw. alle anderen Sitzungen beenden |
| POST | `/api/plugin-manager/scan`, `/api/plugin-manager/{id}/install`, `/api/plugin-manager/{id}/enable`, `/api/plugin-manager/{id}/disable` | neu einlesen, Pakete installieren, ein- und ausblenden (frischer 2FA-Code außer bei `scan`) |
| POST | `/api/plugin-manager/{id}/disable` |
| POST | `/api/plugin-manager/{id}/enable` |
| POST | `/api/plugin-manager/{id}/install` |
| POST | `/api/plugins/apt/check` (prüfen; mit Automatik für Sicherheitsupdates wie `security`) |
| POST | `/api/plugins/apt/security` (prüfen und Sicherheitsupdates installieren) |
| POST | `/api/plugins/apt/settings` (`autoCheck`, `interval` 5–1440 Minuten, `autoSecurity`) |
| POST | `/api/plugins/apt/upgrade` (alles aktualisieren, frischer 2FA-Code) |
| POST | `/api/plugins/fail2ban/unban` |
| POST | `/api/plugins/systemd/action` (`unit`, `action`: `start`, `stop`, `restart`; nicht für GoDebs eigene Units) |
| POST | `/api/plugins/systemd/reboot` (`shutdown -r +1` mit Ankündigung; Passwort und frischer Code; abgelehnt, solange eine APT-Aktion läuft) |
| POST | `/api/plugins/systemd/reboot/cancel` (`shutdown -c`; ohne Code, weil es nur einen Neustart verhindert) |
| POST | `/api/plugins/systemd/reboot/settings` (`auto`, `time` `HH:MM`; `/etc/godeb/reboot.json`) |
| POST | `/api/plugins/ufw/rules` |
| POST | `/api/plugins/wireguard/android/token` |
| POST | `/api/plugins/wireguard/join` (`config`: Beitrittscode oder Client-Datei des Hubs) |
| POST | `/api/plugins/wireguard/peers` |
| POST | `/api/plugins/wireguard/peers/{id}/delete-config` (Client-`.conf` mit privatem Schlüssel löschen; Peer bleibt) |
| POST | `/api/plugins/wireguard/peers/{id}/send-email` |
| POST | `/api/plugins/wireguard/trust` |
| POST | `/api/plugins/wireguard/trust/sync` |
| POST | `/api/plugins/wireguard/volltunnel` |
| POST | `/api/setup/admin` | ohne Login, mit Header `X-GoDeb-Setup-Token`: erster Administrator |
| POST | `/api/setup/finish` | Erreichbarkeit, Trusted Endpoint, Firewall, Abschluss |
| POST | `/api/setup/join` | Peer eines Hubs |
| POST | `/api/user/settings` |
| POST | `/internal/2fa/bind` |
| POST | `/internal/2fa/confirm` |
| POST | `/internal/2fa/enroll` |
| POST | `/internal/2fa/validate` |
| POST | `/internal/trust/sign` |
| PUT | `/api/auth/oidc/providers/{id}` |

## Wartung

- **Logs:** `journalctl -u godeb-play -u godeb-play-agent`; fehlgeschlagene Anmeldungen in `/var/log/godeb-play/auth.log` (für fail2ban).
- **Gesundheit:** `sudo godeb-play doctor` (nur lesend, ohne Geheimnisse), Übersicht der Einrichtung `sudo godeb-play summary`.
- **Updates:** Plugin „Updates“ (APT) wie in GoDeb. Ein APT-Repo für GoDeb Play gibt es noch nicht; neue Versionen kommen als `.deb` aus den Releases.
- **Entfernen:** `apt purge godeb-play` löscht `/etc/godeb-play`, `/var/lib/godeb-play`, `/var/log/godeb-play` und den Benutzer; `/etc/wireguard/wg0.conf` bleibt.

## Entwicklung

Siehe `CLAUDE.md`. Race-Detector: `go test -race ./...`; Fuzz-Tests: `scripts/fuzz.sh [zeit]`.
