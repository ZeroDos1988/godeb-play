#!/bin/sh
# Prints the package version. A tagged commit (vX.Y.Z) is exactly X.Y.Z.
# Any other commit is <last tag or VERSION>+git<commit count>.<short hash>,
# which Debian sorts above the previous build, so apt sees it as an update.
set -eu
cd "$(dirname "$0")/.."
if tag=$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null); then
	echo "${tag#v}"
	exit 0
fi
base=$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)
base=${base#v}
[ -n "$base" ] || base=$(cat VERSION)
count=$(git rev-list --count HEAD)
hash=$(git rev-parse --short=8 HEAD)
suffix=""
if ! git diff --quiet HEAD -- 2>/dev/null; then
	suffix=".dirty"
fi
echo "${base}+git${count}.${hash}${suffix}"
