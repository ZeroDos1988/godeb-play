# Fahrplan GoDeb Play

Stand: 07.11.2026. Reihenfolge = Priorität. `[x]` erledigt, `[ ]` offen. Neue Ideen kommen hierher, Entscheidungen unten.

Konzept (aus dem GoDeb-Fahrplan, 03.11.): Spielserver gehören nicht in GoDeb. GoDeb Play ist ein eigenes, kleines Panel nur für Spielserver, gedacht für einen Container oder eine VM auf dem Heimserver (Proxmox). Es fühlt sich an wie GoDeb (Einrichtung, Login, Optik) und hängt sich wie die Heim-VM als Standort an den GoDeb-Hub.

## Phase 1 – Gerüst (07.11.)

- [x] Repo `ZeroDos1988/godeb-play` (privat) mit dem Unterbau aus GoDeb `24f6000`: Weboberfläche ohne root, root-Agent mit eigener 2FA-Prüfung, Login mit TOTP, Sitzungen, Notfallbefehle, Ersteinrichtung mit Einmal-Token, Plugins Dienste (inkl. Server-Neustart), Firewall, Updates, Protokoll, WireGuard.
- [x] Eigene Namen: Programm `godeb-play`, Dienste `godeb-play(-agent).service`, Benutzer `godeb-play`, Pfade `/etc/godeb-play`, `/var/lib/godeb-play`, Go-Modul `godebplay`. Paket `godeb-play` ohne GoDebs APT-Quelle.
- [x] Entfernt, was nur GoDeb braucht: Mail, Mail-Gateway, Domains/DNS, Webseiten, PostgreSQL, Cron, Zertifikate, App-Zugang, Überwachung, Portweiterleitung, Fail2ban-Seite; im Assistenten und in `godeb-play setup` die Hub-Rolle (eigener WireGuard-Server, Volltunnel, erster Client), `godeb site`.
- [x] Assistent in vier Schritten: Administrator, 2FA, Beitritt zum Hub per Beitrittscode (oder ohne WireGuard zum Ausprobieren), Zugang und Firewall. Ohne Browser: `godeb-play setup --join -`.
- [ ] **(Nutzer) Erster Test im Container:** LXC mit Debian 13 unter Proxmox, Paket bauen und installieren, auf dem Hub `sudo godeb site add spiele`, Beitrittscode im Assistenten einfügen, Oberfläche über den Tunnel öffnen (Adresse aus dem Beitrittscode, z. B. `http://10.8.0.3:8080`). Unprivilegierter LXC braucht für WireGuard das Kernelmodul auf dem Proxmox-Host (`wireguard` ist seit Linux 5.6 im Kernel).

## Phase 2 – Aufräumen des kopierten Unterbaus

- [ ] WireGuard-Plugin auf die Standort-Ansicht zuschneiden: Hub-Teile (Peers anlegen, Volltunnel, APK-Download, Trusted Endpoint für Handys) entfernen; bleiben: Zustand des Tunnels, Handshake, neu beitreten.
- [ ] Übersicht ausdünnen: Kacheln und Abfragen der entfernten Plugins (Überwachung, Fail2ban, Zertifikate) raus, dafür Spielserver-Kacheln (Phase 3).
- [ ] Übersetzungen: Schlüssel der entfernten Plugins aus `de.json`/`en.json` und den übrigen Sprachen löschen.
- [ ] Eigenes Logo (Vorbild GoDeb-Schild, z. B. mit Controller), bis dahin GoDeb-Schriftzug mit „Play“.
- [ ] Zugangsmodus „Fernzugang auf Zeit“ (`godeb-play access open`) prüfen: Ein Container zu Hause hat keine öffentliche IP; vermutlich entfernen.

## Phase 3 – Spielserver

- [ ] SteamCMD-Gerüst und Enshrouded aus GoDeb `346cc85:plugins/steam/` übernehmen: Spiele als Beschreibung (App-ID, Plattform Linux oder Windows unter Wine, Startdatei, Ports, Konfigurationsdatei mit Standardinhalt und Prüfung, optional Formular). Ein Systemkonto und eine Unit pro Spiel, `ProtectSystem=strict`.
- [ ] Wine unter Debian 13: Läuft `enshrouded_server.exe` ohne X-Server? Falls nicht, `xvfb-run` als Option im Unit-Template.
- [ ] Enshrouded-Ports: Neuere Serverversionen kennen nur `queryPort`. GoDeb öffnete zusätzlich `queryPort-1`; nach dem Test ggf. entfernen.
- [ ] Savegame-Backup vor jedem Update und auf Knopfdruck, Wiederherstellen aus der Oberfläche.
- [ ] Spieler und Status per Steam-Query (A2S), Messwerte `game:<id>:up|players|slots`, damit der GoDeb-Hub sie in „Standorte“ zeigen kann.
- [ ] Ports der Spiele nur auf `wg0` (und optional im LAN) in ufw öffnen; die Oberfläche nennt die nötige Weiterleitung am Hub (Plugin „Portweiterleitung“ in GoDeb, Ziel = Adresse dieses Standorts).

## Phase 4 – Später

- [ ] Gekoppelte Verwaltung mit dem Hub (GoDeb-Fahrplan Phase 8): Play schlägt die nötigen Ports vor, der Hub legt die Weiterleitung nach Bestätigung mit 2FA an, nur für die eigene Tunnel-Adresse.
- [ ] Gemeinsames Go-Modul mit GoDeb (nach GoDeb 1.0): `auth`, `agent`, `core`, `db`, `firstrun`, `state`, Teile von `wireguard`, statt Kopien.
- [ ] Paket bzw. Container-Vorlage (Debian 13, LXC unter Proxmox), ein Befehl zum Installieren; eigenes APT-Repo erst, wenn es sich lohnt.

## Entscheidungen

- **Name GoDeb Play** (04.11.).
- **Eigenes, privates Repo** (07.11.): `ZeroDos1988/godeb-play`, vorerst nicht öffentlich.
- **Unterbau kopieren, später teilen** (07.11.): Die Pakete aus GoDeb sind kopiert, damit GoDeb im Feature-Freeze vor 1.0 unberührt bleibt. Nach GoDeb 1.0 wandert das Gemeinsame in ein Go-Modul. Bis dahin Sicherheitsfixes am Unterbau in beiden Repos.
- **Nur Standort, nie Hub** (07.11.): GoDeb Play tritt einem GoDeb-Hub bei oder läuft ohne WireGuard; Hub, Portweiterleitung und Mail bleiben in GoDeb.
- **Eigene Namen** (07.11.): Programm, Dienste, Benutzer und Pfade heißen `godeb-play…`, damit beide Pakete nie kollidieren. Umgebungsvariablen (`GODEB_*`) und Cookie-Namen bleiben gleich.
