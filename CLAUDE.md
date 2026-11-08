# GoDeb Play

Spielserver-Panel für Debian 13 (Trixie) im Container oder in der VM zu Hause: Go-Daemon (`backend/`) + React/Vite (`frontend/`), Plugins unter `plugins/<id>/`.
Hängt sich per WireGuard als Standort an einen GoDeb-Hub (Repo `ZeroDos1988/GoDeb`). Der Unterbau ist aus GoDeb kopiert (Stand `24f6000`, 07.11.2026).
Architektur, API und Sicherheitskonzept stehen in `DOCUMENTATION.md`, offene Arbeit in `ROADMAP.md`.

## Befehle

- Backend-Tests: `go test ./...` (CI zusätzlich `go test -race`); Fuzz-Tests ausführlich: `scripts/fuzz.sh [zeit]`
- Frontend-Build (inkl. Typecheck): `cd frontend && npm run build`
- Paket: `scripts/build-deb.sh` (baut Frontend + statisches Binary, prüft `DEBIAN/control` und `postinst`)
- Gesamtdiagnose ohne Server: `scripts/diagnose.sh` (`--quick` ohne Build/Netz)
- Lokal ohne root starten: `GODEB_DB=$PWD/.dev/godeb.db GODEB_AUTH_DIR=$PWD/.dev/auth GODEB_AUTH_LOG=$PWD/.dev/auth.log GODEB_MASTER_KEY=$PWD/.dev/master.key go run ./backend`
  (fehlende Werkzeuge liefern Beispieldaten mit `mocked: true`)
- Mit Agent lokal (zwei Terminals, gleiche Variablen plus `GODEB_AGENT_SOCKET=$PWD/.dev/agent.sock GODEB_AGENT_DB=$PWD/.dev/agent.db GODEB_STATE_DIR=$PWD/.dev`): `go run ./backend agent`, dann `go run ./backend`

Die Umgebungsvariablen heißen wie in GoDeb (`GODEB_*`); nur Programm, Dienste, Benutzer und Pfade sind umbenannt.

## Entwicklungsrechner nicht verändern

Der Entwicklungsrechner kann selbst GoDeb betreiben. Nichts unter `/etc`, `/usr`, systemd oder APT anfassen.
Pakete nie mit apt, dpkg oder sudo installieren. Fehlt ein Werkzeug: anhalten und dem Nutzer genau einen
fertigen Befehl geben, den er selbst ausführt (mit `sudo`). Gleiches gilt für Deploy (`dpkg -i`, `systemctl restart`).

## Namen (nie mit GoDeb kollidieren)

Programm `/usr/bin/godeb-play`, Paket `godeb-play`, Dienste `godeb-play.service` (Weboberfläche, Benutzer `godeb-play`) und `godeb-play-agent.service` (root, nur Unix-Socket `/run/godeb-play-agent/agent.sock`), Daten `/etc/godeb-play` (Agent, root) und `/var/lib/godeb-play` (Weboberfläche), Log `/var/log/godeb-play`. Go-Modul `godebplay`.

## Sicherheitsregeln (nicht verhandelbar, wie in GoDeb)

GoDeb Play läuft als zwei Prozesse desselben Programms: die Weboberfläche (ohne Rechte) und der Agent (root, nur Unix-Socket). Jede Lücke im Agenten ist root.

- Alles, was das System ändert, läuft im Agenten (`backend/agent`, `newAgentHandler`). Die Weboberfläche leitet `/api/plugins/*`, `/api/plugin-manager*` und die privilegierten Setup-Schritte weiter (`agent.Routed`). Neue privilegierte Routen gehören dorthin, nie in die Weboberfläche.
- Der Agent vertraut der Weboberfläche nicht: Er prüft 2FA für weitergeleitete Änderungen selbst (`auth.AgentGuard`), hält die 2FA-Geheimnisse und liest nichts aus `/var/lib/godeb-play`, wonach er handelt. Daten, nach denen der Agent handelt, liegen in `/etc/godeb-play` (root), über `db.AgentOpen`/`AgentGorm`; Konten und Sitzungen in `/var/lib/godeb-play` über `db.Open`/`Gorm`.
- Schreibt root nach `/var/lib/godeb-play`, dann nur über `state.WriteFile` (os.Root, kein Symlink-Ausbruch, Übergabe an `godeb-play`).
- Interne Agent-Routen (`/internal/…`) nur für Abfragen, die die Weboberfläche nicht selbst lesen darf. Nie eine Route, die 2FA zurücksetzt oder ohne Code etwas ändert.
- Standardmäßig nur auf Loopback und das WireGuard-Interface binden, nie Klartext-HTTP auf LAN/WAN. Ausnahmen nur per HTTPS: die Ersteinrichtung (`backend/firstrun`, Einmal-Token, schließt sich nach Abschluss) und der vom Admin gewählte LAN-Zugang (`access.json`, nur LAN-Subnetz).
- Neue `/api`-Routen sind automatisch geschützt (`auth.RequireSession`). Ausnahmen nur in `auth.protected()` und nur mit Begründung im Kommentar.
- Externe Befehle nur über `core.Run*`/`core.RunAdmin*`: kein `sh -c`, Argumente als Liste, Secrets über stdin.
- Jede Eingabe, die in einem Befehl, Pfad oder einer Konfigdatei landet, gegen eine enge Regex/Allowlist prüfen. Wer eine neue Konfigdatei schreibt (Spielkonfiguration, Units), legt einen Fuzz-Test an.
- Dateien nur über `core.ReadAdminFile`/`WriteAdminFile` (Pfad-Allowlist) oder mit eigener Allowlist im Plugin. Secrets mit Modus `0600`.
- Sensible DB-Felder mit `vault:"secret"` (AES-256-GCM); neue Secret-Spalten in der Agent-DB zusätzlich mit `db.RegisterAgentSecret` anmelden.
- Zustandsändernde Endpunkte nur mit POST/PUT, nie mit GET.
- Spielserver laufen nie als root: ein Systemkonto und eine Unit pro Spiel, `ProtectSystem=strict`, Ports nur auf `wg0` (und optional im LAN).
- Neue Abhängigkeiten nur mit Begründung. Danach `govulncheck ./...` bzw. `npm audit`.

## Architektur

- Rolle immer **Standort** eines GoDeb-Hubs (`wireguard.JoinHub`, Beitrittscode `godeb-join:…`) oder „ohne WireGuard“ zum Ausprobieren. Nie selbst Hub: den Hub verwaltet GoDeb. Die Portweiterleitung am Hub bleibt in GoDeb (Plugin `portforward`).
- Backups macht die Plattform (Proxmox), nicht GoDeb Play. Ausnahme, die noch kommt: Savegames vor Updates (siehe `ROADMAP.md`).
- Das OS ist die Quelle der Wahrheit (`wg0.conf`, systemd, apt). SQLite hält nur Metadaten.
- Kein CGO: `CGO_ENABLED=0`, `-tags netgo`.
- Ein Plugin besteht aus `manifest.json`, `plugin.json`, Go-Paket mit `core.Register` in `init()` plus Blank-Import in `backend/modules.go`, und optional `ui/Panel.tsx`.
- Fehlt ein Werkzeug auf dem Host, liefert die API Beispieldaten und `mocked: true`, statt einen Fehler zu werfen.
- Gleiche Logik für CLI und HTTP: `godeb-play setup` und der Browser-Assistent benutzen dieselben Funktionen.
- Änderungen am kopierten Unterbau, die auch GoDeb betreffen (Sicherheitsfixes in `auth`, `agent`, `core`, `firstrun`), in beiden Repos machen und im Commit auf den jeweils anderen verweisen, bis es das gemeinsame Modul gibt.

## Konventionen

- Fehlermeldungen und UI-Texte auf Deutsch, Code-Kommentare auf Englisch.
- UI-Texte nur über i18n (`frontend/src/locales/*.json`). Neue Schlüssel mindestens in `de.json` und `en.json` (Fallback ist `en`).
- Jede Ansicht muss ab 360 px Breite bedienbar sein: keine festen Breiten, Tabellen in `DataTable`, Formulare einspaltig unter `md`.
- Stil wie GoDeb: `PanelFrame`, `rounded-2xl`, Glas-Optik; Felder, Knöpfe und Karten nur mit den Klassen aus `frontend/src/components/ui.ts`.

## Git: zeitnah committen und pushen (feste Regel)

Ziel: GitHub (`origin`, `git@github.com:ZeroDos1988/godeb-play.git`, öffentlich) ist immer nah am Arbeitsstand.

- Nach jedem abgeschlossenen, getesteten Arbeitspaket sofort committen und pushen, ohne nachzufragen.
- Vor jedem Commit: `go test ./...` und, wenn das Frontend betroffen ist, `cd frontend && npm run build`. Schlägt etwas fehl, wird nicht committet.
- Ein Commit pro logischer Änderung, Conventional Commits (`feat(games): …`, `fix(ui): …`, `build: …`).
- Gezielt stagen (`git add <pfade>`), nie `git add -A`/`.`. Vor dem Commit `git diff --cached` prüfen: keine Secrets (`master.key`, `*.db`, `.dev/`, Client-Configs, private Schlüssel), keine Build-Artefakte (`*.deb`, `dist/`).
- Commit-Identität ist `ZeroDos1988 <336650567+ZeroDos1988@users.noreply.github.com>` (in `.git/config` gesetzt). Nie einen Klarnamen oder eine private Mailadresse in Commits, Dateien oder Releases.
- Kein `--force`, kein Umschreiben gepushter Historie, keine Tags/Releases ohne Auftrag.
