# Sicherheit

GoDeb Play verwaltet Spielserver mit root-Rechten (der Agent `godeb-play-agent.service` läuft als root). Sicherheitslücken bitte **nicht** als öffentliches Issue melden.

## Lücke melden

Über GitHub: Reiter **Security** → **Report a vulnerability** (privat, nur für die Maintainer sichtbar).

Hilfreich sind:

- betroffene Version (`godeb-play version`) und Rolle (Standort eines Hubs oder ohne WireGuard),
- Schritte zum Nachvollziehen, betroffene Route oder Datei,
- was ein Angreifer damit erreicht (z. B. Code als root, Umgehen der 2FA, Lesen fremder Daten).

Eine erste Antwort kommt in der Regel innerhalb einer Woche. Eine behobene Lücke wird mit einer neuen Version und einem Security Advisory veröffentlicht.

## Unterstützte Versionen

GoDeb Play ist eine Vorabversion (`0.x`). Fehler werden nur in der jeweils neuesten Version behoben; bitte vor einer Meldung auf den neuesten Release aktualisieren.

## Grenzen des Sicherheitsmodells

Das Sicherheitskonzept steht in [DOCUMENTATION.md](DOCUMENTATION.md#sicherheitskonzept). Kurz: Die Weboberfläche ist nur über Loopback und WireGuard erreichbar, läuft ohne Rechte, und der root-Agent prüft jede Änderung selbst mit einem 2FA-Code. Wer root auf dem Server hat oder die 2FA-Geräte eines Admins besitzt, ist nicht Teil des Bedrohungsmodells.
