#!/bin/sh
# Runs every fuzz test of GoDeb for a while. Each one feeds random input to
# a validation whose output lands in a config file or command (nginx, Sieve,
# systemd units, wg0.conf, nftables, mail maps) and checks that the output
# keeps its structure.
#
#   scripts/fuzz.sh [zeit pro test, Standard 60s]
#
# A finding is saved under <package>/testdata/fuzz/<Test>/ and fails the run;
# commit that file with the fix, it then runs with every go test.
set -eu
cd "$(dirname "$0")/.."
time=${1:-60s}
fail=0
for pkg in $(go list ./...); do
	for fn in $(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true); do
		echo "==> $pkg $fn ($time)"
		# Short minimisation: by default every new input is shrunk for up to
		# a minute, which stalls the run.
		if ! go test "$pkg" -run '^$' -fuzz "^$fn\$" -fuzztime "$time" -fuzzminimizetime 10x; then
			fail=1
		fi
	done
done
exit "$fail"
