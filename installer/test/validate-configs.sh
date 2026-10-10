#!/usr/bin/env bash
# Validate every configuration file bpanel-installer generates with the real
# tools, on a scratch Debian/Ubuntu machine or container (it changes /etc and
# restores it afterwards). Needs: nginx apache2 php-fpm postfix openssh-server
# fail2ban logrotate systemd.
#
#   sudo installer/test/validate-configs.sh ./bin/bpanel-installer
#
# Checks per profile (minimal, web, full):
#   nginx -t, apache2ctl configtest, php-fpmX.Y -t, postfix check, sshd -t,
#   fail2ban-client --test + fail2ban-regex on the panel filter, logrotate -d,
#   systemd-analyze verify, systemd-analyze security (agent unit),
#   systemd-tmpfiles --dry-run, nft -c (when the kernel allows netlink).
set -uo pipefail

BPI="$(readlink -f "${1:?usage: validate-configs.sh /path/to/bpanel-installer}")"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
PHPV="$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1 | sed 's,.*php-fpm,,')"
FAILS=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$*"; }
check() { local name="$1"; shift; local out; if out="$("$@" 2>&1)"; then pass "$name"; else fail "$name"; echo "$out" | sed 's/^/        /' | tail -15; fi; }

BACKUP="$(mktemp -d /tmp/bpanel-validate-backup.XXXXXX)"
SAVED=(/etc/nginx /etc/apache2 /etc/php /etc/postfix /etc/ssh /etc/fail2ban /etc/aliases /etc/logrotate.d /etc/tmpfiles.d /etc/systemd/system /etc/bpanel /etc/systemd/resolved.conf.d /etc/systemd/journald.conf.d)
for p in "${SAVED[@]}"; do [ -e "$p" ] && mkdir -p "$BACKUP$(dirname "$p")" && cp -a "$p" "$BACKUP$p"; done
restore() {
  for p in "${SAVED[@]}"; do rm -rf "$p"; [ -e "$BACKUP$p" ] && cp -a "$BACKUP$p" "$p"; done
  rm -f /usr/local/bin/bpanel-agent /usr/local/bin/bpanel-api
  userdel bpvalidate 2>/dev/null
  rm -rf "$BACKUP"
}
trap restore EXIT

# prerequisites the installer's "system" stage creates
for g in bpanel bpanel-web bpanel-sftp bpanel-users; do getent group "$g" >/dev/null || groupadd --system "$g"; done
getent passwd bpanel >/dev/null || useradd --system -g bpanel -d /var/lib/bpanel/db -s /usr/sbin/nologin bpanel
getent passwd bpanel-apps >/dev/null || useradd --system --user-group -d /var/lib/bpanel/apps -s /usr/sbin/nologin bpanel-apps
mkdir -p /etc/bpanel/ssl/panel /var/log/bpanel/domlogs /var/lib/bpanel/apps/{sessions,pma-tmp,roundcube}
chown root:bpanel /var/log/bpanel /var/log/bpanel/domlogs; chmod 0750 /var/log/bpanel /var/log/bpanel/domlogs
[ -s /etc/bpanel/ssl/panel/fullchain.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj /CN=panel.example.com -keyout /etc/bpanel/ssl/panel/privkey.pem -out /etc/bpanel/ssl/panel/fullchain.pem 2>/dev/null
ssh-keygen -A >/dev/null 2>&1
for b in bpanel-agent bpanel-api; do [ -e /usr/local/bin/$b ] || ln -s /bin/true /usr/local/bin/$b; done

for PROFILE in minimal web full; do
  echo "== profile $PROFILE (Debian layout, PHP $PHPV, $(nginx -v 2>&1))"
  # start every profile from the distribution's files
  for p in /etc/nginx /etc/apache2 /etc/php /etc/postfix /etc/ssh /etc/fail2ban /etc/aliases; do
    rm -rf "$p"; [ -e "$BACKUP$p" ] && cp -a "$BACKUP$p" "$p"
  done
  OUT="$(mktemp -d)"
  "$BPI" render --profile "$PROFILE" --hostname panel.example.com --email admin@example.com --out "$OUT" >/dev/null || { fail "render"; continue; }
  # PHP files are rendered for the layout's default version; map them to the installed one
  for f in $(cd "$OUT" && find . -type f); do
    dst="/${f#./}"
    dst="$(echo "$dst" | sed -E "s,/etc/php/[0-9.]+/,/etc/php/$PHPV/,; s,php[0-9.]+-fpm\.service\.d,php$PHPV-fpm.service.d,")"
    mkdir -p "$(dirname "$dst")"; cp "$OUT/$f" "$dst"
  done

  # nginx: the installer moves sites-enabled/default aside
  rm -f /etc/nginx/sites-enabled/default; mkdir -p /etc/nginx/bpanel.d
  check "nginx -t" nginx -t
  if [ "$PROFILE" = full ]; then
    if grep -q 'http2 on;' /etc/nginx/bpanel-apps.d/apps.conf; then pass "webmail uses 'http2 on;' (nginx >= 1.25.1)"; else fail "webmail http2 form"; fi
  fi
  if [ "$(grep -c '^gzip on;' /etc/nginx/conf.d/bpanel.conf)" = 0 ] && grep -q '^\s*gzip on;' /etc/nginx/nginx.conf; then pass "SYS-1: stock 'gzip on' not duplicated"; else fail "SYS-1 gzip"; fi

  if [ "$PROFILE" != minimal ]; then
    mkdir -p /etc/apache2/bpanel.d
    a2dissite -q 000-default >/dev/null 2>&1; a2dismod -q -f mpm_prefork >/dev/null 2>&1
    a2enmod -q mpm_event proxy proxy_fcgi setenvif rewrite headers remoteip expires >/dev/null
    a2enconf -q bpanel >/dev/null
    check "apache2ctl configtest" apache2ctl configtest
    if grep -q '^Listen 127.0.0.1:8080' /etc/apache2/ports.conf; then pass "Apache backend on 127.0.0.1:8080"; else fail "apache ports"; fi
  else
    if [ -e /etc/apache2/conf-available/bpanel.conf ] && ! cmp -s /etc/apache2/conf-available/bpanel.conf "$BACKUP/etc/apache2/conf-available/bpanel.conf" 2>/dev/null; then
      fail "SYS-5: minimal profile rendered Apache files"; else pass "SYS-5: minimal profile writes no Apache config"; fi
  fi

  check "php-fpm$PHPV -t" "/usr/sbin/php-fpm$PHPV" -t

  if [ "$PROFILE" = full ]; then
    install -d /etc/postfix/bpanel
    for m in vdomains vmailbox valias; do echo "# test" > /etc/postfix/bpanel/$m; postmap hash:/etc/postfix/bpanel/$m; done
    mapfile -t PC < "$OUT/postconf-e.txt"
    postconf -e "${PC[@]}"
    newaliases
    for svc in submission smtps; do postconf -M "$svc/inet=$svc inet n - y - - smtpd"; done
    postconf -P "submission/inet/smtpd_tls_security_level=encrypt" "smtps/inet/smtpd_tls_wrappermode=yes"
    check "postfix check" postfix check
    if postalias -q root hash:/etc/aliases | grep -q admin@example.com; then pass "root mail alias -> admin@example.com"; else fail "root alias"; fi
    if [ "$(postconf -h mydestination)" = '$myhostname, localhost.localdomain, localhost' ]; then pass "local delivery for \$myhostname"; else fail "mydestination"; fi
  fi

  check "sshd -t" sshd -t
  getent passwd bpvalidate >/dev/null || useradd -M -d /home/bpvalidate -s /usr/sbin/nologin -G bpanel-sftp bpvalidate
  EFF="$(sshd -T -C user=bpvalidate,host=client.example,addr=203.0.113.1 2>&1)"
  if echo "$EFF" | grep -qi '^chrootdirectory /home$' && echo "$EFF" | grep -qi '^forcecommand internal-sftp -d /%u$' && echo "$EFF" | grep -qi '^permittty no$'; then
    pass "SFTP jail applies to bpanel-sftp members"; else fail "sshd -T -C (SFTP jail)"; echo "$EFF" | grep -iE 'chroot|forcecommand|error' | sed 's/^/        /'; fi
  ROOTEFF="$(sshd -T -C user=root,host=client.example,addr=203.0.113.1 2>&1)"
  if echo "$ROOTEFF" | grep -qi '^chrootdirectory none$'; then pass "SFTP jail does not touch other users"; else fail "jail leaks to root"; fi
  check "fail2ban-client --test" fail2ban-client --test
  LINE='time=2026-10-09T12:00:00.000+03:00 level=WARN msg="auth failure" realm=admin user=bob ip=203.0.113.9 reason="bad credentials"'
  if fail2ban-regex "$LINE" /etc/fail2ban/filter.d/bpanel.conf 2>/dev/null | grep -q 'Failregex: 1 total'; then pass "fail2ban panel filter matches the API line"; else fail "fail2ban-regex panel filter"; fi
  LINE6='level=WARN msg="auth failure" realm=user user=x ip=2001:db8::7'
  if fail2ban-regex "$LINE6" /etc/fail2ban/filter.d/bpanel.conf 2>/dev/null | grep -q 'Failregex: 1 total'; then pass "fail2ban panel filter matches IPv6"; else fail "fail2ban-regex IPv6"; fi
  if fail2ban-regex 'level=INFO msg="login ok" ip=203.0.113.9' /etc/fail2ban/filter.d/bpanel.conf 2>/dev/null | grep -q 'Failregex: 0 total'; then pass "fail2ban panel filter ignores successful logins"; else fail "fail2ban false positive"; fi

  check "logrotate -d" logrotate -d /etc/logrotate.d/bpanel
  check "systemd-analyze verify units" systemd-analyze verify /etc/systemd/system/bpanel-agent.service /etc/systemd/system/bpanel-api.service /etc/systemd/system/bpanel-firewall.service
  check "systemd-tmpfiles --dry-run" systemd-tmpfiles --dry-run --create /etc/tmpfiles.d/bpanel.conf
  if out="$(nft -c -f /etc/bpanel/nftables.conf 2>&1)"; then pass "nft -c"; elif echo "$out" | grep -qi 'netlink\|Operation not permitted\|Protocol not supported'; then skip "nft -c (no nf_tables netlink in this sandbox)"; else fail "nft -c"; echo "$out" | sed 's/^/        /'; fi
  rm -rf "$OUT"
done

echo "== systemd-analyze security (exposure score, lower is better)"
for u in bpanel-agent bpanel-api; do
  printf '  %-14s ' "$u"; systemd-analyze security --offline=true --no-pager "/etc/systemd/system/$u.service" 2>/dev/null | tail -1
done

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "$FAILS CHECK(S) FAILED"; fi
exit "$FAILS"
