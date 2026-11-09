# Fahrplan GoDeb Play

Stand: 09.11.2026. Reihenfolge = Priorität. `[x]` erledigt, `[ ]` offen. Offene Punkte tragen, wer oder was sie erledigt: **(Nutzer)** nur mit echter Hardware bzw. beim Nutzer, **(nach GoDeb 1.0)** wartet auf das Ende des Feature-Freeze in GoDeb, **(später)** erst wenn es sich lohnt. Neue Ideen kommen hierher, Entscheidungen unten.

Konzept (aus dem GoDeb-Fahrplan, 03.11.): Spielserver gehören nicht in GoDeb. GoDeb Play ist ein eigenes, kleines Panel nur für Spielserver, gedacht für einen Container oder eine VM auf dem Heimserver (Proxmox). Es fühlt sich an wie GoDeb (Einrichtung, Login, Optik) und hängt sich wie die Heim-VM als Standort an den GoDeb-Hub.

## Phase 1 – Gerüst (07.11.)

- [x] Repo `ZeroDos1988/godeb-play` (seit 08.11. öffentlich) mit dem Unterbau aus GoDeb `24f6000`: Weboberfläche ohne root, root-Agent mit eigener 2FA-Prüfung, Login mit TOTP, Sitzungen, Notfallbefehle, Ersteinrichtung mit Einmal-Token, Plugins Dienste (inkl. Server-Neustart), Firewall, Updates, Protokoll, WireGuard.
- [x] Eigene Namen: Programm `godeb-play`, Dienste `godeb-play(-agent).service`, Benutzer `godeb-play`, Pfade `/etc/godeb-play`, `/var/lib/godeb-play`, Go-Modul `godebplay`. Paket `godeb-play` ohne GoDebs APT-Quelle.
- [x] Assistent in vier Schritten: Administrator, 2FA, Beitritt zum Hub per Beitrittscode (oder ohne WireGuard zum Ausprobieren), Zugang und Firewall. Ohne Browser: `godeb-play setup --join -`.
- [ ] **(Nutzer) Erster Test im Container:** LXC mit Debian 13 unter Proxmox (Befehle in `DOCUMENTATION.md` „Container unter Proxmox“), auf dem Hub `sudo godeb site add spiele`, Beitrittscode im Assistenten, Oberfläche über den Tunnel öffnen, Neustart des Containers (Tunnel und Spielserver kommen wieder).

## Phase 2 – Aufräumen des kopierten Unterbaus (07.11.)

- [x] WireGuard-Seite als Standort-Ansicht (Zustand, Hub, Handshake, Traffic, neu beitreten); Peers anlegen, QR, Client-Dateien, Mailversand, Volltunnel, APK-Download und Hub-Init entfernt.
- [x] Trusted Endpoint entfernt (bietet zu Hause die GoDeb-Heim-VM an; hier wäre er ein weiterer unauthentifizierter Endpunkt im LAN) und Fernzugang auf Zeit entfernt (keine öffentliche IP im Container). Öffentliche Ausnahmen für die entfernten Routen ebenfalls.
- [x] Übersicht mit Spielserver-Kachel statt Fail2ban und Zertifikaten.
- [x] Übersetzungen der entfernten Plugins in allen sieben Sprachen gelöscht (de/en etwa halb so groß).
- [x] Überwachung (Plugin `monitor`) zurückgeholt: Der Hub holt den Zustand des Standorts samt Spielern über `/api/plugins/monitor/site`.
- [ ] **(Nutzer) Eigenes Logo** (wie beim GoDeb-Logo, z. B. mit Gemini: Schild mit Controller). Bis dahin GoDeb-Schriftzug mit „Play“. Dateien nach `docs/brand/` und `frontend/public/`.

## Phase 3 – Spielserver (07.11.)

- [x] SteamCMD-Gerüst und Enshrouded aus GoDeb `346cc85:plugins/steam/` übernommen: Spiele als Beschreibung, ein Systemkonto und eine Unit (`godeb-play-<spiel>.service`) pro Spiel, `ProtectSystem=strict`, Formular und Datei-Editor für die Konfiguration, Job-Log, Server-Log.
- [x] **Sicherheitsfix** gegenüber dem alten Plugin: Der root-Agent folgte im Spielverzeichnis Symlinks (Temp-Datei der Konfiguration mit `chown`, `chownTree`, Entpacken, Neuinstallation, Lesen der Konfiguration). Ein übernommener Spielserver hätte so beliebige Dateien dem Spielkonto übergeben lassen können. Jetzt alles über `os.Root`, mit Tests, die genau diese Symlinks anlegen.
- [x] Savegame-Backup vor jedem Update, auf Knopfdruck und vor jeder Wiederherstellung, Wiederherstellen aus der Oberfläche; root-only, die letzten zehn.
- [x] Firewall: als Standort nur `wg0`, ohne WireGuard nur das Heimnetz (vorher öffentlich).
- [x] Spieler und Status per Steam-Query (A2S), Messwerte für den Hub; Hinweis auf die nötige Portweiterleitung im Hub.
- [x] Installieren, Update und Wiederherstellen mit Passwort und frischem Code; Fuzz-Test für die Enshrouded-Konfiguration.
- [x] **GE-Proton statt Wine für Enshrouded** (09.11.): festgelegte Version mit geprüfter SHA-256, root-eigen und für alle Spiele gemeinsam, Präfix pro Spiel; Wine aus Debian bleibt als Plattform für andere Spiele. Entpacken des echten Archivs geprüft (identisch zu `tar`).
- [ ] **(Nutzer) GE-Proton unter Debian 13:** Startet `enshrouded_server.exe` mit `proton run` ohne X-Server und mit den Paketen `python3`, `libfreetype6`, `libgnutls30t64`? Falls ein X-Server nötig ist: `xvfb-run` als Option im Unit-Template (Paket `xvfb`). Fehlende Bibliotheken stehen im Server-Log.
- [ ] **(Nutzer) Enshrouded-Ports:** Neuere Serverversionen kennen nur `queryPort`. GoDeb Play öffnet zusätzlich `queryPort-1`, solange kein `gamePort` gesetzt ist; nach dem Test ggf. entfernen.
- [ ] **(Nutzer) Backup und Wiederherstellen** einmal mit einem echten Savegame ausprobieren.

## Phase 4 – Später

- [ ] **(nach GoDeb 1.0) Gekoppelte Verwaltung mit dem Hub** (GoDeb-Fahrplan Phase 8): Play schlägt die nötigen Ports vor, der Hub legt die Weiterleitung nach Bestätigung mit 2FA an, nur für die eigene Tunnel-Adresse. Braucht Änderungen in GoDeb, deshalb erst nach dessen Feature-Freeze.
- [ ] **(nach GoDeb 1.0) Gemeinsames Go-Modul mit GoDeb:** `auth`, `agent`, `core`, `db`, `firstrun`, `state`, Teile von `wireguard`, statt Kopien. Bis dahin Sicherheitsfixes am Unterbau in beiden Repos.
- [x] **Weitere Spiele** (07.11.): Valheim und Satisfactory, je mit Prüfung und Tests. Weitere (z. B. Palworld) nach demselben Muster.
- [ ] **(Nutzer) Valheim und Satisfactory** einmal auf echter Hardware starten: Ports, App-IDs und Startparameter stammen aus den Herstelleranleitungen.
- [x] **Eigenes APT-Repo vorbereitet** (07.11.): eigener Signierschlüssel (`~/.config/godeb-play-apt`), `scripts/build-apt-repo.sh`, Workflow `apt-repo.yml`, Prüfung des Schlüsselablaufs in `security.yml`. Lokal mit echtem `apt-get update` geprüft.
- [x] **APT-Repo eingebunden** (08.11.): Release-Job ruft `apt-repo.yml` auf, Paket bringt `godeb-play.sources` und Schlüssel mit, Diagnose prüft Pages.
- [ ] **(Nutzer) APT-Repo live schalten:** Repo öffentlich, Secret `APT_SIGNING_KEY` setzen, Pages mit Quelle „GitHub Actions“, dann erstes Release (Tag `v…`).
- [x] **Aufräumen im WireGuard-Paket** (07.11.): Hub- und Client-Teile (`clients.go`, `hub.go`, `cidr.go`) und die Standort-Abfrage der Überwachung entfernt; die WireGuard-Seite liest nur noch `wg0.conf` und `wg show`.

## Entscheidungen

- **Name GoDeb Play** (04.11.).
- **Eigenes Repo** (07.11.): `ZeroDos1988/godeb-play`, zuerst privat, seit 08.11. öffentlich, damit das APT-Repo auf GitHub Pages ohne bezahltes Konto geht.
- **Unterbau kopieren, später teilen** (07.11.): Die Pakete aus GoDeb sind kopiert, damit GoDeb im Feature-Freeze vor 1.0 unberührt bleibt. Nach GoDeb 1.0 wandert das Gemeinsame in ein Go-Modul. Bis dahin Sicherheitsfixes am Unterbau in beiden Repos.
- **Nur Standort, nie Hub** (07.11.): GoDeb Play tritt einem GoDeb-Hub bei oder läuft ohne WireGuard; Hub, Portweiterleitung und Mail bleiben in GoDeb.
- **Eigene Namen** (07.11.): Programm, Dienste, Benutzer und Pfade heißen `godeb-play…`, damit beide Pakete nie kollidieren. Umgebungsvariablen (`GODEB_*`) und Cookie-Namen bleiben gleich.
- **APT-Repo wie bei GoDeb** (08.11.): erst nur vorbereitet, weil Pages immer öffentlich ist; mit dem öffentlichen Repo freigeschaltet.
- **Kein Trusted Endpoint, kein Fernzugang** (07.11.): Beides gibt es in GoDeb; im Container zu Hause wären es nur zusätzliche Angriffsflächen.
- **Savegame-Backups trotz „Backups macht die Plattform“** (07.11.): Proxmox sichert den Container; Savegames zusätzlich, weil ein kaputtes Spiel-Update sonst nur durch Zurückspielen des ganzen Containers zu beheben wäre.
