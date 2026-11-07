<p align="center"><img src="docs/brand/godeb-logo-horizontal.png" alt="GoDeb" width="320"></p>

# GoDeb Play

**Spielserver-Panel für den Heimserver, das sich per WireGuard an einen GoDeb-Hub hängt.**

GoDeb Play läuft in einem Container oder einer VM zu Hause (z. B. LXC unter Proxmox) und kennt nur Spielserver. Es tritt einem [GoDeb](https://github.com/ZeroDos1988/GoDeb)-Hub als Standort bei; Spieler erreichen die Server dann über die öffentliche IP des VPS, ohne Portfreigabe am Heimrouter, auch hinter CGNAT oder DS-Lite.

```text
Spieler --> VPS (GoDeb-Hub, öffentliche IP) --DNAT/SNAT--> WireGuard --> GoDeb Play 10.8.0.3
                                                                          + Spielserver
```

> **Stand:** Gerüst. Einrichtung, Login mit 2FA, Agent und Beitritt zum Hub funktionieren; Spielserver (SteamCMD, Enshrouded) folgen. Siehe [ROADMAP.md](ROADMAP.md).

## Was es mit GoDeb teilt

Der Unterbau ist aus GoDeb kopiert (Stand GoDeb `24f6000`, 07.11.2026) und soll nach GoDeb 1.0 in ein gemeinsames Go-Modul wandern:

- **Weboberfläche ohne root**, Systemänderungen nur im root-Agenten über einen Unix-Socket; der Agent prüft jeden 2FA-Code selbst.
- **Ersteinrichtung im Browser** mit Einmal-Token, erster Administrator, TOTP-2FA mit Backup-Codes.
- **Nur über Tunnel, Heimnetz (HTTPS) oder lokal** erreichbar, nie Klartext-HTTP auf LAN oder WAN.
- **Beitritt per Beitrittscode** (`godeb-join:…`) mit derselben strengen Prüfung der Client-Datei wie in GoDeb.
- Plugins für Dienste (inkl. Server-Neustart), Firewall (ufw), Updates (APT), Protokoll und WireGuard.

GoDeb Play hat eigene Namen, damit es nie mit GoDeb kollidiert: Programm `godeb-play`, Dienste `godeb-play.service` und `godeb-play-agent.service`, Benutzer `godeb-play`, Daten in `/etc/godeb-play` und `/var/lib/godeb-play`.

## Installation (zum Testen)

Noch kein APT-Repo. Paket bauen und im Container installieren:

```sh
scripts/build-deb.sh
sudo apt install --no-install-recommends ./godeb-play_*_amd64.deb
```

Auf dem GoDeb-Hub einen Standort anlegen (`sudo godeb site add spiele` oder WireGuard → „+ GoDeb-Server zu Hause“), dann den Link aus der Installation öffnen (`sudo godeb-play setup-url`) und im Assistenten den Beitrittscode einfügen. Ohne Browser: `sudo godeb-play setup --join -`.

## Entwicklung

Befehle und Regeln stehen in [CLAUDE.md](CLAUDE.md), Architektur und API in [DOCUMENTATION.md](DOCUMENTATION.md).

## Lizenz

GPL-3.0, siehe [LICENSE](LICENSE).
