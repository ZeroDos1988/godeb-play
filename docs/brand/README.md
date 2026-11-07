# GoDeb – Logo

Entworfen am 29.10.2026 mit Hilfe von Google Gemini; die Dateien hier sind daraus ausgeschnitten, freigestellt und skaliert.

| Datei | Größe | Verwendung |
| --- | --- | --- |
| `godeb-shield.png` | 865 × 964, transparent | Ausgangsdatei des Schilds, für neue Größen |
| `godeb-wordmark.png` | 1140 × 248, transparent | Ausgangsdatei des Schriftzugs |
| `godeb-logo-horizontal.png` | Schild + Schriftzug, transparent | README, Dokumente |
| `godeb-icon-512.png` | 512 × 512, transparent | App-Icon |
| `godeb-social-preview.png` | 1280 × 640, dunkel | GitHub → Settings → General → Social preview |

Die Oberfläche nutzt Kopien in `frontend/public/`: `logo.png` (Schild, 256 px hoch), `wordmark.png` (64 px hoch), `favicon-16.png`, `favicon-32.png`, `apple-touch-icon.png` (180 px, heller Hintergrund), `icon-192.png`, `icon-512.png`. Eingebunden über `frontend/src/components/Brand.tsx`.

## Farben

| | Hex |
| --- | --- |
| Cyan („Go“, G) | `#14afdd` |
| Rot („Deb“, D) | `#c9395c` |
| Schild hell / dunkel | `#203e60` / `#1b3452` |

## Hinweise

- Das Logo ist eine Rastergrafik aus einer KI-Vorlage, keine Vektordatei. Für Druck in großen Formaten oder eine SVG-Fassung müsste es einmal nachgezeichnet werden.
- Die Spirale im „D“ erinnert an den Debian-Swirl, ist aber eine eigene Form und nicht das Debian-Logo. GoDeb ist kein offizielles Debian-Projekt; das Debian-Logo selbst wird nicht verwendet (Debian-Markenrichtlinie: https://www.debian.org/trademark).
