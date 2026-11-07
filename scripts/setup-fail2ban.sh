#!/bin/sh
# Configures fail2ban for the GoDeb web port and the SSH daemon.
# Run as root. The Debian package calls it from postinst.
set -eu

GODEB_LOG=/var/log/godeb-play/auth.log
FILTER=/etc/fail2ban/filter.d/godeb-play.conf
JAIL=/etc/fail2ban/jail.d/godeb-play.local
SSHD_JAIL=/etc/fail2ban/jail.d/godeb-play-sshd.local

if [ "$(id -u)" -ne 0 ]; then
	echo "setup-fail2ban.sh muss als root laufen" >&2
	exit 1
fi

if ! command -v fail2ban-client >/dev/null 2>&1; then
	if [ -n "${DPKG_MAINTSCRIPT_PACKAGE:-}" ]; then
		# apt cannot run while dpkg holds its lock; Depends: fail2ban covers this case.
		echo "fail2ban fehlt. Danach erneut ausführen: apt-get install -y fail2ban && $0" >&2
		exit 0
	fi
	DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
fi

install -d -m 0750 "$(dirname "$GODEB_LOG")"
# fail2ban refuses to start a jail whose logpath does not exist.
[ -e "$GODEB_LOG" ] || install -m 0640 /dev/null "$GODEB_LOG"
install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d

cat >"$FILTER" <<'EOF'
# Managed by godeb-play (scripts/setup-fail2ban.sh)
[Definition]
failregex = ^.* FAILED_LOGIN ip=<HOST>.*$
ignoreregex =
EOF

# backend = auto overrides a global "backend = systemd" from defaults-debian.conf,
# which would otherwise make fail2ban ignore logpath.
cat >"$JAIL" <<'EOF'
# Managed by godeb-play (scripts/setup-fail2ban.sh)
[godeb-play]
enabled = true
port = 8080,8443
filter = godeb-play
logpath = /var/log/godeb-play/auth.log
backend = auto
# Every failed login step counts: unknown name (step 1), wrong password
# (step 2), wrong 2FA or backup code (step 3). Five within 10 minutes ban
# the address for 10 minutes; each further ban of the same address lasts
# twice as long, at most a day.
maxretry = 5
findtime = 600
bantime = 600
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 86400
EOF

if [ -x /usr/sbin/sshd ]; then
	{
		echo "# Managed by godeb-play (scripts/setup-fail2ban.sh)"
		echo "[sshd]"
		echo "enabled = true"
		# Debian 13 logs sshd to the journal only unless rsyslog is installed.
		if [ ! -e /var/log/auth.log ]; then
			echo "backend = systemd"
		fi
	} >"$SSHD_JAIL"
else
	rm -f "$SSHD_JAIL"
	echo "openssh-server ist nicht installiert, sshd-Jail bleibt aus" >&2
fi

if ! fail2ban-client -t >/dev/null 2>&1; then
	echo "fail2ban-Konfiguration ungültig:" >&2
	fail2ban-client -t >&2 || true
	exit 1
fi

systemctl enable fail2ban.service >/dev/null 2>&1 || true
systemctl restart fail2ban.service

for _ in 1 2 3 4 5 6 7 8 9 10; do
	fail2ban-client ping >/dev/null 2>&1 && break
	sleep 1
done
fail2ban-client status
