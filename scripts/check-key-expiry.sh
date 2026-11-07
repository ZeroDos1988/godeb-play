#!/bin/sh
# Fails when a key of the APT repo (package/apt/godeb-play-archive-keyring.asc)
# expires within the given number of days (default 90). Run weekly by
# .github/workflows/security.yml. Renewing the signing subkey needs the
# primary key in ~/.config/godeb-play-apt (see ROADMAP, "Eigenes APT-Repo").
set -eu
cd "$(dirname "$0")/.."
days=${1:-90}
limit=$(( $(date -u +%s) + days * 86400 ))
fail=0
for exp in $(sq inspect package/apt/godeb-play-archive-keyring.asc | sed -n 's/^ *Expiration time: \([0-9-]*\) .*/\1/p'); do
	if [ "$(date -u -d "$exp" +%s)" -lt "$limit" ]; then
		echo "Schlüssel des APT-Repos läuft am $exp ab (weniger als $days Tage)" >&2
		fail=1
	else
		echo "Schlüssel gültig bis $exp"
	fi
done
exit "$fail"
