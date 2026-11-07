#!/bin/sh
# Project diagnosis: everything that can be checked without a server.
# Prints one line per check (OK / WARN / FAIL) plus details, and exits 1 if
# anything failed. Used by the /diagnose skill (.claude/skills/diagnose).
#
#   scripts/diagnose.sh          all checks
#   scripts/diagnose.sh --quick  without frontend build, mail check and network
#
# Changes nothing in the repository or on the system; temporary files go
# to /tmp.
set -u
cd "$(dirname "$0")/.."
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1
FAILS=0
WARNS=0
ok() { printf 'OK    %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
detail() { sed 's/^/      /'; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== Git"
branch=$(git rev-parse --abbrev-ref HEAD)
git fetch -q origin main --tags 2>/dev/null || warn "git fetch fehlgeschlagen (offline?)"
if [ -n "$(git status --porcelain)" ]; then
	warn "Arbeitsbaum nicht sauber ($branch)"
	git status --short | head -20 | detail
else
	ok "Arbeitsbaum sauber ($branch)"
fi
ahead=$(git rev-list --count origin/main..HEAD 2>/dev/null || echo "?")
behind=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "?")
[ "$ahead" = 0 ] && [ "$behind" = 0 ] && ok "gleich mit origin/main" || warn "gegenüber origin/main: $ahead voraus, $behind zurück"
tag=$(git describe --tags --abbrev=0 origin/main 2>/dev/null || echo "")
if [ -n "$tag" ]; then
	n=$(git rev-list --count "$tag"..origin/main)
	[ "$n" = 0 ] && ok "letztes Release $tag ist main" || warn "letztes Release $tag, seitdem $n Commits auf main (unveröffentlicht)"
	git log --oneline "$tag"..origin/main | grep -v "docs(roadmap)" | head -15 | detail
fi

echo "== Go"
if [ -n "$(gofmt -l backend plugins 2>/dev/null)" ]; then
	warn "gofmt: nicht formatiert"
	gofmt -l backend plugins | detail
else
	ok "gofmt"
fi
if go vet ./... >"$TMP/vet" 2>&1; then ok "go vet"; else fail "go vet"; detail <"$TMP/vet"; fi
if go test -count=1 ./... >"$TMP/test" 2>&1; then
	ok "go test ($(grep -c '^ok' "$TMP/test") Pakete)"
else
	fail "go test"
	grep -v '^ok\|no test files' "$TMP/test" | head -40 | detail
fi
vuln="govulncheck"
command -v govulncheck >/dev/null 2>&1 || vuln="go run golang.org/x/vuln/cmd/govulncheck@latest"
if $vuln ./... >"$TMP/vuln" 2>&1; then ok "govulncheck"; else fail "govulncheck"; tail -30 "$TMP/vuln" | detail; fi

echo "== Frontend"
if [ "$QUICK" = 0 ]; then
	if [ ! -d frontend/node_modules ]; then (cd frontend && npm ci --no-audit --no-fund >/dev/null 2>&1); fi
	if (cd frontend && npm run build >"$TMP/build" 2>&1); then ok "npm run build (inkl. tsc)"; else fail "npm run build"; tail -30 "$TMP/build" | detail; fi
	if (cd frontend && npm audit --omit=dev >"$TMP/audit" 2>&1); then ok "npm audit --omit=dev"; else warn "npm audit meldet etwas"; tail -15 "$TMP/audit" | detail; fi
else
	echo "      übersprungen (--quick)"
fi

echo "== Übersetzungen"
python3 - <<'EOF' >"$TMP/i18n" 2>&1
import json, re, glob, sys
def keys(d, p=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from keys(v, p + k + ".")
        else:
            yield p + k
de = set(keys(json.load(open("frontend/src/locales/de.json"))))
en = set(keys(json.load(open("frontend/src/locales/en.json"))))
used = set()
for f in glob.glob("frontend/src/**/*.tsx", recursive=True) + glob.glob("plugins/*/ui/**/*.tsx", recursive=True):
    for m in re.finditer(r'\bt\(\s*"([a-zA-Z0-9_.]+)"', open(f).read()):
        used.add(m.group(1))
out = []
for k in sorted(de - en): out.append(f"nur in de.json: {k}")
for k in sorted(en - de): out.append(f"nur in en.json: {k}")
plural = lambda k: k in de or any(x.startswith(k + "_") for x in de)
for k in sorted(used):
    if not plural(k): out.append(f"benutzt, fehlt in de.json: {k}")
print("\n".join(out))
sys.exit(1 if out else 0)
EOF
if [ $? = 0 ]; then ok "de/en vollständig, alle benutzten Schlüssel vorhanden"; else warn "Übersetzungen"; head -30 "$TMP/i18n" | detail; fi

echo "== API und Doku"
grep -rhoE 'HandleFunc\("(GET|POST|PUT|DELETE) [^"]+' backend plugins --include=*.go --exclude=*_test.go |
	sed -E 's/HandleFunc\("(GET|POST|PUT|DELETE) //; s/"\+?base\+"/\/api\/plugins\/mail/' | sort -u >"$TMP/routes"
# Routes built from a prefix variable ("GET "+base+"/x") show up as the suffix only.
missing=0
for r in $(grep '^/api/' "$TMP/routes" | sort -u); do
	short=$(printf '%s' "$r" | sed -E 's/\{[^}]+\}/{/g')
	if ! sed -E 's/\{[^}]+\}/{/g' DOCUMENTATION.md | grep -qF "$short"; then
		echo "$r" >>"$TMP/undoc"
		missing=$((missing + 1))
	fi
done
[ "$missing" = 0 ] && ok "alle API-Routen in DOCUMENTATION.md" || { warn "$missing API-Routen nicht in DOCUMENTATION.md"; detail <"$TMP/undoc"; }
for p in $(sed -n 's#.*_ "godebplay/plugins/\([a-z0-9]*\).*#\1#p' backend/modules.go); do
	[ -f "plugins/$p/manifest.json" ] || fail "Plugin $p ohne manifest.json"
	[ -f "plugins/$p/plugin.json" ] || fail "Plugin $p ohne plugin.json"
done
ok "Plugins in backend/modules.go haben manifest.json und plugin.json"

echo "== Sicherheitsregeln (CLAUDE.md)"
if grep -rnE '"sh", "-c"|"bash", "-c"|"/bin/sh", "-c"' backend plugins --include=*.go | grep -v _test >"$TMP/shc"; then
	fail "sh -c gefunden"; detail <"$TMP/shc"
else
	ok "kein sh -c"
fi
grep -rlnE 'exec\.Command(Context)?\(' backend plugins --include=*.go | grep -v _test | grep -vE 'backend/core/exec.go' >"$TMP/exec" || true
[ -s "$TMP/exec" ] && { warn "exec.Command außerhalb von core (prüfen)"; detail <"$TMP/exec"; } || ok "externe Befehle über core.Run*"
# The OIDC start is a GET by protocol (browser redirect to the provider).
grep -rnE 'HandleFunc\("GET [^"]*/(delete|create|install|start|stop|restart|set|enable|disable|flush|upgrade|revoke)("|/)' backend plugins --include=*.go --exclude=*_test.go | grep -v '/api/auth/oidc/{id}/start' >"$TMP/getmut" || true
[ -s "$TMP/getmut" ] && { fail "GET-Route mit Änderungs-Namen"; detail <"$TMP/getmut"; } || ok "keine ändernden GET-Routen (nach Namen)"
if grep -rnE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' --include=* -l . 2>/dev/null | grep -vE '^\./(frontend/node_modules|\.git)/' | grep -v '_test.go' >"$TMP/keys"; then
	fail "privater Schlüssel im Repo"; detail <"$TMP/keys"
else
	ok "keine privaten Schlüssel im Repo"
fi
if git ls-files | grep -E '\.(db|deb)$|master\.key|(^|/)\.dev/' >"$TMP/files"; then fail "verbotene Dateien versioniert"; detail <"$TMP/files"; else ok "keine *.db, *.deb, master.key, .dev/ im Repo"; fi

if [ "$QUICK" = 0 ]; then
	echo "== CI und Releases"
	if command -v gh >/dev/null 2>&1; then
		gh run list --branch main -L 3 --json conclusion,displayTitle,workflowName --jq '.[] | "\(.conclusion)\t\(.workflowName)\t\(.displayTitle)"' >"$TMP/ci" 2>&1
		if grep -q '^failure' "$TMP/ci"; then fail "CI auf main"; else ok "CI auf main"; fi
		detail <"$TMP/ci"
		latest=$(gh release list -L 1 --json tagName --jq '.[0].tagName' 2>/dev/null)
		ok "letztes GitHub-Release: ${latest:-keines}"
	else
		warn "gh fehlt, CI nicht geprüft"
	fi
fi

echo
echo "Ergebnis: $FAILS Fehler, $WARNS Warnungen"
[ "$FAILS" = 0 ]
