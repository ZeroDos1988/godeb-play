#!/bin/sh
# Builds the signed APT repository for GitHub Pages from released packages.
#
#   scripts/build-apt-repo.sh <stable dir> <testing dir> <output dir> <signing key>
#
# Two suites share one pool:
#   trixie          releases (not marked as pre-release); servers in production
#   trixie-testing  every release including pre-releases
# The stable dir may be empty only as long as there is no stable release at
# all (before 1.0); trixie then carries the testing packages, so existing
# installations keep their updates.
#
# The signing key is the OpenPGP key without the primary's secret
# (~/.config/godeb-play-apt/ci-signing.pgp, in the CI the secret
# APT_SIGNING_KEY).
# Needs apt-ftparchive (apt-utils) and sq.
set -eu

if [ $# -ne 4 ]; then
	echo "Aufruf: $0 <stabil-verzeichnis> <test-verzeichnis> <ausgabe> <signierschlüssel>" >&2
	exit 2
fi
cd "$(dirname "$0")/.."
ROOT=$(pwd)
STABLE=$(cd "$1" && pwd)
TESTING=$(cd "$2" && pwd)
mkdir -p "$3"
OUT=$(cd "$3" && pwd)
KEY=$4

COMPONENT=main
ARCHS="amd64 arm64"
POOL="pool/$COMPONENT/g/godeb-play"

set -- "$TESTING"/godeb-play_*_amd64.deb
if [ ! -e "$1" ]; then
	echo "Keine amd64-Pakete in $TESTING" >&2
	exit 1
fi
set -- "$STABLE"/godeb-play_*_amd64.deb
if [ ! -e "$1" ]; then
	echo "Noch kein stabiles Release: trixie enthält die Vorabversionen" >&2
	STABLE=$TESTING
fi

rm -rf "$OUT/dists" "$OUT/pool"
mkdir -p "$OUT/$POOL"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# collect <suite> <dir>: copies the packages into the shared pool and links
# them into a per-suite tree, from which apt-ftparchive builds the index
# with Filename paths that point into the shared pool.
collect() {
	mkdir -p "$WORK/$1/$POOL"
	for arch in $ARCHS; do
		for deb in "$2"/godeb-play_*_"$arch".deb; do
			[ -e "$deb" ] || continue
			if [ "$(dpkg-deb -f "$deb" Package)" != godeb-play ] || [ "$(dpkg-deb -f "$deb" Architecture)" != "$arch" ]; then
				echo "Kein GoDeb-Play-Paket für $arch: $deb" >&2
				exit 1
			fi
			name=$(basename "$deb")
			if [ -e "$OUT/$POOL/$name" ]; then
				cmp -s "$deb" "$OUT/$POOL/$name" || {
					echo "$name unterscheidet sich zwischen den Suiten" >&2
					exit 1
				}
			else
				cp "$deb" "$OUT/$POOL/"
			fi
			ln -sf "$OUT/$POOL/$name" "$WORK/$1/$POOL/$name"
		done
	done
}

# index <codename> <suite label>: Packages, Release, InRelease, Release.gpg.
index() {
	dists="$OUT/dists/$1"
	for arch in $ARCHS; do
		mkdir -p "$dists/$COMPONENT/binary-$arch"
		packages="$dists/$COMPONENT/binary-$arch/Packages"
		(cd "$WORK/$1" && apt-ftparchive --arch "$arch" packages "pool/$COMPONENT") >"$packages"
		gzip -9nk "$packages"
	done
	(cd "$OUT" && apt-ftparchive \
		-o APT::FTPArchive::Release::Origin="GoDeb Play" \
		-o APT::FTPArchive::Release::Label="GoDeb Play" \
		-o APT::FTPArchive::Release::Suite="$2" \
		-o APT::FTPArchive::Release::Codename="$1" \
		-o APT::FTPArchive::Release::Architectures="$ARCHS" \
		-o APT::FTPArchive::Release::Components="$COMPONENT" \
		-o APT::FTPArchive::Release::Description="GoDeb Play for Debian 13 ($2)" \
		release "dists/$1") >"$WORK/Release"
	mv "$WORK/Release" "$dists/Release"

	sq sign --batch --signer-file "$KEY" --cleartext --output "$dists/InRelease" "$dists/Release"
	sq sign --batch --signer-file "$KEY" --signature-file "$dists/Release.gpg" "$dists/Release"

	# Verify with the shipped key, the way apt on Trixie does it (sqv).
	sqv --keyring "$keyring" "$dists/Release.gpg" "$dists/Release" >/dev/null
	# sqv refuses to overwrite its output, so it writes into a fresh directory.
	check=$(mktemp -d)
	sqv --keyring "$keyring" --message --output "$check/Release" "$dists/InRelease" >/dev/null
	cmp -s "$check/Release" "$dists/Release"
	rm -rf "$check"
}

keyring="$ROOT/package/apt/godeb-play-archive-keyring.asc"
collect trixie "$STABLE"
collect trixie-testing "$TESTING"
index trixie stable
index trixie-testing testing
count=$(find "$OUT/$POOL" -name '*.deb' | wc -l)

# Files for the manual setup; identical to the ones in the package, so dpkg
# takes over godeb-play.sources without a conffile prompt.
cp "$keyring" "$OUT/godeb-play-archive-keyring.asc"
cp "$ROOT/package/debian/etc/apt/sources.list.d/godeb-play.sources" "$OUT/godeb-play.sources"
sed 's/^Suites: trixie$/Suites: trixie-testing/' "$OUT/godeb-play.sources" >"$OUT/godeb-play-testing.sources"
grep -q '^Suites: trixie-testing$' "$OUT/godeb-play-testing.sources"
fingerprint=$(sed -n 's/^Comment: \([0-9A-F ]\{50\}\)$/\1/p' "$keyring")
cat >"$OUT/index.html" <<EOF
<!doctype html>
<html lang="de">
<meta charset="utf-8">
<title>GoDeb Play APT-Repository</title>
<h1>GoDeb Play APT-Repository</h1>
<p>Für Debian 13 (Trixie), amd64 und arm64. Mit einem Konto mit sudo (als root ohne <code>sudo</code>):</p>
<pre>sudo wget -O /usr/share/keyrings/godeb-play-archive-keyring.asc https://zerodos1988.github.io/godeb-play/godeb-play-archive-keyring.asc
sudo wget -O /etc/apt/sources.list.d/godeb-play.sources https://zerodos1988.github.io/godeb-play/godeb-play.sources
sudo apt update
sudo apt install --no-install-recommends godeb-play</pre>
<p>Vorabversionen zum Testen (nicht für Produktivserver) zusätzlich einschalten:</p>
<pre>sudo wget -O /etc/apt/sources.list.d/godeb-play-testing.sources https://zerodos1988.github.io/godeb-play/godeb-play-testing.sources
sudo apt update</pre>
<p>Fingerprint des Schlüssels: <code>$fingerprint</code></p>
</html>
EOF
echo "Fertig: $OUT ($count Pakete)"
