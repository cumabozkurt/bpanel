#!/bin/bash
# BPANEL E2E for the core rows (v0.1–v0.3 features: domains, files, DNS, mail, FTP, databases,
# backups, SSL, logs, PHP, cron, account security, WHM account lifecycle, services, settings).
# Runs INSIDE a disposable server/container as root, against the real services.
# Site checks after the ssl section follow redirects (-L): once AutoSSL has issued a certificate
# the vhost redirects HTTP to HTTPS.
#   BP_ADMIN_PASS=… BP_TAG=… BP_OUT=… ./core.sh [section ...]
cd "$(dirname "$0")"
source ./lib.sh
STATE="$BP_OUT/state.env"; touch "$STATE"; source "$STATE"
save() { for v in "$@"; do sed -i "/^$v=/d" "$STATE"; printf '%s=%q\n' "$v" "${!v}" >> "$STATE"; done; }
ev() { cat > "$BP_OUT/ev/$1"; }
: "${C:=c${BP_TAG}}"; : "${CDOM:=${C}.${BP_TLD}}"; : "${CPASS:=CorePass${RANDOM}q7}"; save C CDOM CPASS
CH=/home/$C
reauth() { api admin POST /api/v1/account/reauth /api/v1/account/reauth "$(jq -nc --arg p "$BP_ADMIN_PASS" '{password:$p}')"; }
creauth() { api cu POST /api/v1/account/reauth /api/v1/account/reauth "$(jq -nc --arg p "$CPASS" '{password:$p}')"; }
web() { curl -s -m 20 --noproxy '*' --resolve "$1:80:127.0.0.1" --resolve "$1:443:127.0.0.1" -k "${@:2}"; }
export -f web
next_window() { sleep $(( 31 - $(date +%s) % 30 )); }
fop() { api cu POST /api/v1/user/files /api/v1/user/files "$1"; }
SECTIONS=(setup domains files dns mail ftp databases backups ssl logs php cron security prefs admin services lifecycle api)
[ $# -gt 0 ] && SECTIONS=("$@")

s_setup() {
  ROLE_OF_SESSION=admin login admin admin "$BP_ADMIN_USER" "$BP_ADMIN_PASS"; check c-setup "admin login" code_is 200
  api admin GET /api/v1/admin/packages /api/v1/admin/packages; PKG=$(jqb '[.. | objects | select(.disk_mb? != null)][0].id'); save PKG
  api admin POST /api/v1/admin/packages /api/v1/admin/packages "{\"name\":\"core-$BP_TAG\",\"disk_mb\":2000,\"bandwidth_mb\":10000,\"max_domains\":3,\"max_subdomains\":5,\"max_aliases\":3,\"max_email\":10,\"max_db\":3,\"max_ftp\":3,\"mail_quota_mb\":200}"
  check packages "create package core-$BP_TAG" code_2xx; CPKG=$(jqb '.id // .package.id'); save CPKG
  api admin PUT '/api/v1/admin/packages/{id}' "/api/v1/admin/packages/$CPKG" "{\"name\":\"core-$BP_TAG\",\"disk_mb\":3000,\"bandwidth_mb\":10000,\"max_domains\":3,\"max_subdomains\":5,\"max_aliases\":3,\"max_email\":10,\"max_db\":3,\"max_ftp\":3,\"mail_quota_mb\":200}"
  check packages "edit package (disk 3000 MB)" code_2xx
  api admin POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"$C\",\"domain\":\"$CDOM\",\"email\":\"owner@$BP_TLD\",\"password\":\"$CPASS\",\"package_id\":$CPKG,\"role\":\"user\"}"
  check accounts "create account $C (system user, vhost, zone, PHP-FPM pool)" code_is 200; CID=$(jqb '.account.id'); save CID
  check accounts "system user + home exist" bash -c "id $C && [ -d $CH/public_html ]"
  check accounts "site served by nginx" bash -c "[ \$(web $CDOM -o /dev/null -w '%{http_code}' http://$CDOM/) = 200 ]"
  check accounts "zone served by PowerDNS" bash -c "dig +short @127.0.0.1 $CDOM SOA | grep -q ."
  ROLE_OF_SESSION=user login cu user "$C" "$CPASS"; check c-setup "user login" code_is 200
  api cu GET /api/v1/user/domains /api/v1/user/domains; CDID=$(echo "$BODY" | jq -r --arg n "$CDOM" '[.. | objects | select(.name? == $n)][0].id'); save CDID
}

s_domains() {
  local add="add${BP_TAG}.${BP_TLD}"
  api cu POST /api/v1/user/domains /api/v1/user/domains "{\"kind\":\"addon\",\"name\":\"$add\",\"docroot\":\"$add\"}"; check domains "addon domain $add" code_2xx
  printf '<h1>addon %s</h1>' "$BP_TAG" > /tmp/addon.html; install -o "$C" -g "$C" -m 644 /tmp/addon.html "$CH/$add/index.html" 2>/dev/null || cp /tmp/addon.html "$CH/$add/index.html"
  check domains "addon domain served from its docroot" bash -c "web $add http://$add/ | grep -q 'addon $BP_TAG'"
  check domains "addon zone created" bash -c "dig +short @127.0.0.1 $add SOA | grep -q ."
  api cu POST /api/v1/user/domains /api/v1/user/domains "{\"kind\":\"sub\",\"name\":\"blog\",\"parent_id\":$CDID,\"docroot\":\"blog\"}"; check domains "subdomain blog.$CDOM" code_2xx
  check domains "subdomain A record" bash -c "dig +short @127.0.0.1 blog.$CDOM A | grep -q ."
  check domains "subdomain vhost answers" bash -c "[ \$(web blog.$CDOM -o /dev/null -w '%{http_code}' http://blog.$CDOM/) != 000 ]"
  api cu POST /api/v1/user/domains /api/v1/user/domains "{\"kind\":\"alias\",\"name\":\"alias${BP_TAG}.${BP_TLD}\",\"parent_id\":$CDID}"; check domains "alias (parked) domain" code_2xx
  echo "<h1>main $BP_TAG</h1>" > "$CH/public_html/index.html"; chown "$C:$C" "$CH/public_html/index.html"
  check domains "alias serves the main site" bash -c "web alias${BP_TAG}.${BP_TLD} http://alias${BP_TAG}.${BP_TLD}/ | grep -q 'main $BP_TAG'"
  api cu GET /api/v1/user/domains /api/v1/user/domains; local aid; aid=$(echo "$BODY" | jq -r --arg n "$add" '[.. | objects | select(.name? == $n)][0].id')
  api cu PUT '/api/v1/user/domains/{id}' "/api/v1/user/domains/$aid" '{"redirect":"https://example.org/landing"}'; check redirects "redirect addon -> https://example.org/landing" code_2xx
  check redirects "301 with Location" bash -c "web $add -o /dev/null -D - http://$add/x | grep -Eiq '^HTTP/1.1 30[12]' && web $add -o /dev/null -D - http://$add/ | grep -iq '^location: https://example.org/landing'"
  api cu PUT '/api/v1/user/domains/{id}' "/api/v1/user/domains/$aid" '{"redirect":""}'; check redirects "redirect removed" code_2xx
  check redirects "addon served again" bash -c "sleep 1; web $add http://$add/ | grep -q 'addon $BP_TAG'"
  api cu POST /api/v1/user/domains /api/v1/user/domains '{"kind":"addon","name":"../etc","docroot":"x"}'; check domains "invalid domain name refused" code_4xx
}

s_files() {
  fop '{"op":"mkdir","path":"public_html/fm"}'; check files "mkdir" code_2xx
  fop '{"op":"write","path":"public_html/fm/a.txt","content":"hello file manager"}'; check files "write file" code_2xx
  check files "file on disk, owned by the account" bash -c "[ \$(stat -c %U $CH/public_html/fm/a.txt) = $C ] && grep -q 'hello file manager' $CH/public_html/fm/a.txt"
  fop '{"op":"read","path":"public_html/fm/a.txt"}'; check files "read file" bash -c "echo '$BODY' | grep -q 'hello file manager'"
  fop '{"op":"copy","path":"public_html/fm/a.txt","dest":"public_html/fm/b.txt"}'; check files "copy" code_2xx
  fop '{"op":"rename","path":"public_html/fm/b.txt","dest":"public_html/fm/c.txt"}'; check files "rename" code_2xx
  fop '{"op":"chmod","path":"public_html/fm/c.txt","mode":384}'; check files "chmod 0600" bash -c "[ \$(stat -c %a $CH/public_html/fm/c.txt) = 600 ]"
  fop '{"op":"zip","paths":["public_html/fm/a.txt","public_html/fm/c.txt"],"dest":"public_html/fm/z.zip"}'; check files "zip" bash -c "[ -s $CH/public_html/fm/z.zip ] || { echo '$CODE ${BODY:0:200}'; false; }"
  fop '{"op":"list","path":"public_html/fm"}'; check files "list" bash -c "echo '$BODY' | grep -q c.txt"
  echo "uploaded $BP_TAG" > /tmp/up.txt
  local out; out=$("${CURL[@]}" -b "$BP_OUT/jars/cu.jar" -H "X-CSRF-Token: $(cat $BP_OUT/jars/cu.csrf)" -H "Origin: $USER_URL" -F path=public_html/fm -F "file=@/tmp/up.txt" -w '\n%{http_code}' "$USER_URL/api/v1/user/files/upload"); CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"; cover POST /api/v1/user/files/upload user "$CODE"
  check files "upload (multipart)" bash -c "[[ $CODE == 2* ]] && grep -q 'uploaded $BP_TAG' $CH/public_html/fm/up.txt"
  check files "download" bash -c "curl -sk -m 30 --noproxy '*' -b $BP_OUT/jars/cu.jar '$USER_URL/api/v1/user/files/download?path=public_html/fm/up.txt' | grep -q 'uploaded $BP_TAG'"; cover GET /api/v1/user/files/download user 200
  fop '{"op":"read","path":"../../etc/shadow"}'; check files "path traversal refused" code_4xx
  ln -sf /etc/shadow "$CH/public_html/fm/evil" 2>/dev/null; chown -h "$C:$C" "$CH/public_html/fm/evil"
  fop '{"op":"read","path":"public_html/fm/evil"}'; check files "symlink escape refused" bash -c "[[ $CODE == 4* ]] && ! echo '$BODY' | grep -q 'root:'"
  fop '{"op":"delete","paths":["public_html/fm"]}'; check files "delete" bash -c "[[ $CODE == 2* ]] && [ ! -e $CH/public_html/fm ]"
  api cu GET /api/v1/user/disk /api/v1/user/disk; check disk "disk usage (dirs, databases, mail)" code_is 200; echo "$BODY" | ev core-disk.json
}

s_dns() {
  api cu GET '/api/v1/user/dns/{domain}' "/api/v1/user/dns/$CDOM"; check zone "get zone" code_is 200; echo "$BODY" | ev core-zone.json
  api cu PUT '/api/v1/user/dns/{domain}/rrset' "/api/v1/user/dns/$CDOM/rrset" "{\"name\":\"probe.$CDOM\",\"type\":\"TXT\",\"ttl\":300,\"records\":[\"\\\"core-$BP_TAG\\\"\"]}"; check zone "add TXT record" code_2xx
  check zone "record served (dig)" bash -c "dig +short @127.0.0.1 probe.$CDOM TXT | grep -q core-$BP_TAG"
  api cu PUT '/api/v1/user/dns/{domain}/rrset' "/api/v1/user/dns/$CDOM/rrset" "{\"name\":\"www2.$CDOM\",\"type\":\"A\",\"ttl\":300,\"records\":[\"192.0.2.44\"]}"; check zone "add A record" code_2xx
  check zone "A record served" bash -c "dig +short @127.0.0.1 www2.$CDOM A | grep -qx 192.0.2.44"
  api cu DELETE '/api/v1/user/dns/{domain}/rrset/{name}/{type}' "/api/v1/user/dns/$CDOM/rrset/probe.$CDOM/TXT"; check zone "delete record" code_2xx
  check zone "record gone" bash -c "[ -z \"\$(dig +short @127.0.0.1 probe.$CDOM TXT)\" ]"
  api cu PUT '/api/v1/user/dns/{domain}/rrset' "/api/v1/user/dns/other${BP_TAG}.org/rrset" '{"name":"x.other.org","type":"A","ttl":300,"records":["192.0.2.1"]}'; check zone "foreign zone refused" code_4xx
}

s_mail() {
  local MP="BoxPass${RANDOM}z9"; CMP=$MP; save CMP
  api cu POST /api/v1/user/email/accounts /api/v1/user/email/accounts "{\"domain\":\"$CDOM\",\"local\":\"user1\",\"password\":\"$MP\",\"quota_mb\":100}"; check email "create mailbox user1@$CDOM" code_2xx
  api cu POST /api/v1/user/email/accounts /api/v1/user/email/accounts "{\"domain\":\"$CDOM\",\"local\":\"user2\",\"password\":\"$MP\",\"quota_mb\":100}"
  check email "IMAP login (Dovecot, TLS)" bash -c "curl -s -m 20 --noproxy '*' -k --url imaps://127.0.0.1/ --user 'user1@$CDOM:$MP' -X 'LIST \"\" \"*\"' | grep -qi inbox"
  check email "wrong password refused" bash -c "! curl -s -m 20 --noproxy '*' -k --url imaps://127.0.0.1/ --user 'user1@$CDOM:nope' -X 'LIST \"\" \"*\"' | grep -qi inbox"
  check email "authenticated submission (587 STARTTLS) delivers" bash -c "swaks -s 127.0.0.1:587 -tls -au 'user1@$CDOM' -ap '$MP' -f 'user1@$CDOM' -t 'user2@$CDOM' --h-Subject 'submit-$BP_TAG' >/dev/null && sleep 4 && grep -rlqs 'submit-$BP_TAG' $CH/mail/$CDOM/user2"
  # from a non-loopback source (127.0.0.0/8 is in mynetworks, as on every Postfix default)
  ip addr add 192.0.2.77/32 dev lo 2>/dev/null
  swaks -s 127.0.0.1 -li 192.0.2.77 -f 'x@example.org' -t 'victim@example.net' > "$BP_OUT/ev/core-relay.txt" 2>&1
  check email "unauthenticated relay from outside refused (554 Relay access denied)" grep -q 'Relay access denied' "$BP_OUT/ev/core-relay.txt"
  ip addr del 192.0.2.77/32 dev lo 2>/dev/null
  check email "DKIM signature on outgoing mail" bash -c "f=\$(grep -rls 'submit-$BP_TAG' $CH/mail/$CDOM/user2/new $CH/mail/$CDOM/user2/cur | head -1); grep -qi '^DKIM-Signature:' \"\$f\""
  api cu POST /api/v1/user/email/forwarders /api/v1/user/email/forwarders "{\"domain\":\"$CDOM\",\"source\":\"sales\",\"destination\":\"user2@$CDOM\"}"; check forwarders "forwarder sales@ -> user2@" code_2xx
  swaks -s 127.0.0.1 -f probe@example.org -t "sales@$CDOM" --h-Subject "fwd-$BP_TAG" >/dev/null 2>&1; sleep 4
  check forwarders "forwarded mail delivered" bash -c "grep -rlqs 'fwd-$BP_TAG' $CH/mail/$CDOM/user2"
  api cu POST /api/v1/user/email/forwarders /api/v1/user/email/forwarders "{\"domain\":\"$CDOM\",\"source\":\"*\",\"destination\":\"user1@$CDOM\"}"; check catchall "default address (catch-all) -> user1@" code_2xx
  swaks -s 127.0.0.1 -f probe@example.org -t "nobody-$RANDOM@$CDOM" --h-Subject "catch-$BP_TAG" >/dev/null 2>&1; sleep 4
  check catchall "unknown recipient caught" bash -c "grep -rlqs 'catch-$BP_TAG' $CH/mail/$CDOM/user1"
  api cu GET /api/v1/user/email/deliverability /api/v1/user/email/deliverability; check deliverability "SPF/DKIM/DMARC status" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -qi dkim"; echo "$BODY" | ev core-deliverability.json
  check deliverability "SPF, DKIM, DMARC records published" bash -c "dig +short @127.0.0.1 $CDOM TXT | grep -q 'v=spf1' && dig +short @127.0.0.1 _dmarc.$CDOM TXT | grep -q DMARC1 && dig +short @127.0.0.1 bpanel._domainkey.$CDOM TXT | grep -q 'p='"
  api cu GET /api/v1/user/email/accounts /api/v1/user/email/accounts; check email-disk "mailbox usage reported" bash -c "echo '$BODY' | grep -q 'user1@$CDOM'"
  api cu GET /api/v1/user/webmail /api/v1/user/webmail; check webmail "webmail URL" code_is 200; local wu; wu=$(jqb .url)
  check webmail "Roundcube answers" bash -c "curl -sk -m 20 --noproxy '*' '$(echo "$wu" | sed 's#//[^:/]*#//127.0.0.1#')' | grep -qi roundcube"
}

s_ftp() {
  local FP="FtpPass${RANDOM}x4"
  api cu POST /api/v1/user/ftp /api/v1/user/ftp "{\"login\":\"up\",\"domain\":\"$CDOM\",\"password\":\"$FP\",\"dir\":\"public_html\",\"quota_mb\":50}"; check ftp "create FTP account" code_2xx
  api cu GET /api/v1/user/ftp /api/v1/user/ftp; local fl; fl=$(echo "$BODY" | jq -r '[.. | objects | select(.login? != null) | .login][0]'); echo "$BODY" | ev core-ftp.json
  echo "via ftp $BP_TAG" > /tmp/ftp.txt
  check ftp "upload over FTPS (Pure-FTPd, explicit TLS)" bash -c "curl -s -m 30 --noproxy '*' --ssl-reqd -k -T /tmp/ftp.txt 'ftp://127.0.0.1/ftp.txt' --user '$fl:$FP' && grep -q 'via ftp $BP_TAG' $CH/public_html/ftp.txt"
  check ftp "uploaded file owned by the account" bash -c "[ \$(stat -c %U $CH/public_html/ftp.txt) = $C ]"
  check ftp "FTP chroot: / is the account dir" bash -c "curl -s -m 30 --noproxy '*' --ssl-reqd -k 'ftp://127.0.0.1/' --user '$fl:$FP' | grep -q ftp.txt && ! curl -s -m 30 --noproxy '*' --ssl-reqd -k 'ftp://127.0.0.1/../../etc/' --user '$fl:$FP' | grep -q passwd"
  check ftp "wrong password refused" bash -c "! curl -s -m 30 --noproxy '*' --ssl-reqd -k 'ftp://127.0.0.1/' --user '$fl:nope' >/dev/null"
}

s_databases() {
  api cu POST /api/v1/user/db-wizard /api/v1/user/db-wizard "{\"name\":\"shop\",\"user\":\"shop\",\"password\":\"DbWizard${RANDOM}x7k\",\"all\":true}"; check mysql "database wizard (db + user + grant)" code_2xx; echo "$BODY" | ev core-dbwizard.json
  check mysql "database exists in MariaDB with the grant" bash -c "mysql -N -e \"SHOW GRANTS FOR '${C}_shop'@'localhost'\" | grep -q '${C}_shop'"
  api cu POST /api/v1/user/phpmyadmin /api/v1/user/phpmyadmin; check phpmyadmin "single-sign-on URL" code_2xx; local u; u=$(jqb '.url // empty')
  check phpmyadmin "phpMyAdmin opens logged in (SSO, proxied on 2083)" bash -c "cp $BP_OUT/jars/cu.jar $BP_OUT/pma.jar; curl -skL -m 30 --noproxy '*' -c $BP_OUT/pma.jar -b $BP_OUT/pma.jar '$USER_URL$u' > $BP_OUT/ev/core-pma.html; grep -qi 'phpmyadmin' $BP_OUT/ev/core-pma.html && grep -q '${C}_shop' $BP_OUT/ev/core-pma.html"
}

s_backups() {
  echo "backup me $BP_TAG" > "$CH/public_html/keep.txt"; chown "$C:$C" "$CH/public_html/keep.txt"
  creauth; api cu POST /api/v1/user/backups /api/v1/user/backups '{"databases":true}'; check backups "run backup now (restic)" code_2xx; echo "$BODY" | ev core-backup-run.json
  local i snap=""; for i in $(seq 1 60); do api cu GET /api/v1/user/backups /api/v1/user/backups; snap=$(jqb '[.. | objects | select((.short_id? != null) and ((.tags // []) | index("files"))) | .short_id][0] // empty' 2>/dev/null); [ -n "$snap" ] && [ "$snap" != null ] && break; sleep 3; done
  echo "$BODY" | ev core-backups.json
  check backups "snapshot listed" bash -c "[ -n '$snap' ] && [ '$snap' != null ]"
  rm -f "$CH/public_html/keep.txt"
  creauth; api cu POST /api/v1/user/backups/restore /api/v1/user/backups/restore "{\"snapshot\":\"$snap\",\"path\":\"public_html/keep.txt\",\"in_place\":true}"; check restore "restore one file" code_2xx; echo "$BODY" | ev core-restore.json
  check restore "file restored with its content" bash -c "for i in \$(seq 1 30); do grep -qs 'backup me $BP_TAG' $CH/public_html/keep.txt && exit 0; sleep 2; done; exit 1"
}

s_ssl() {
  # The container trusts a local Pebble ACME test CA (BPANEL_ACME_DIRECTORY + LEGO_CA_CERTIFICATES
  # in a systemd drop-in of bpanel-agent): the real lego HTTP-01 flow runs against it, and Pebble
  # validates over port 80 of this server after resolving the name through PowerDNS.
  api cu GET /api/v1/user/ssl /api/v1/user/ssl; check ssl "SSL/TLS status per domain" code_is 200
  creauth; api cu POST /api/v1/user/ssl/autossl /api/v1/user/ssl/autossl "{\"domain_id\":$CDID}"; echo "$BODY" | ev core-autossl.json
  check ssl "AutoSSL issues a certificate (ACME HTTP-01 against Pebble)" bash -c "[[ $CODE == 2* ]] && echo '$BODY' | jq -e '.present == true' >/dev/null || { echo '$CODE ${BODY:0:300}'; false; }"
  check ssl "HTTPS vhost serves the issued certificate" bash -c "sleep 2; echo | openssl s_client -connect 127.0.0.1:443 -servername $CDOM 2>/dev/null | openssl x509 -noout -issuer -subject -ext subjectAltName | tee $BP_OUT/ev/core-cert.txt | grep -qi pebble && grep -q '$CDOM' $BP_OUT/ev/core-cert.txt"
  check ssl "site answers over HTTPS" bash -c "web $CDOM https://$CDOM/ | grep -q 'main $BP_TAG'"
  check ssl "legacy TLS 1.1 refused" bash -c "! echo | openssl s_client -connect 127.0.0.1:443 -servername $CDOM -tls1_1 2>/dev/null | grep -q 'BEGIN CERTIFICATE'"
  api cu GET /api/v1/user/ssl /api/v1/user/ssl; echo "$BODY" | ev core-ssl.json; check ssl "status shows the certificate and its expiry" bash -c "echo '$BODY' | grep -q 'not_after\\|notAfter\\|expires'"
}

s_logs() {
  web "$CDOM" -L -o /dev/null "http://$CDOM/core-log-probe-$BP_TAG"; sleep 2
  api cu GET /api/v1/user/logs "/api/v1/user/logs?domain=$CDOM&kind=access"; check logs "raw access log contains the request" bash -c "echo '$BODY' | grep -q core-log-probe-$BP_TAG"
  api cu GET /api/v1/user/logs "/api/v1/user/logs?domain=$CDOM&kind=error"; check logs "error log readable" code_is 200
  api cu GET /api/v1/user/logs "/api/v1/user/logs?domain=other.example&kind=access"; check logs "foreign domain refused" code_4xx
}

s_php() {
  api cu GET /api/v1/user/php /api/v1/user/php; check php "installed PHP versions" code_is 200; echo "$BODY" | ev core-php.json
  local v; v=$(jqb '[.. | strings | select(test("^[0-9]+\\.[0-9]+$"))][0]')
  echo '<?php echo "php=".PHP_VERSION." user=".get_current_user();' > "$CH/public_html/v.php"; chown "$C:$C" "$CH/public_html/v.php"
  check php "PHP runs through the account's FPM pool" bash -c "web $CDOM -L http://$CDOM/v.php | grep -q 'php=$v'"
  check php "FPM worker runs as the account user" bash -c "ps -eo user:32,args | grep 'php-fpm: pool' | grep -q '^$C '"
  api cu PUT '/api/v1/user/domains/{id}' "/api/v1/user/domains/$CDID" "{\"php_version\":\"$v\"}"; check php "set domain PHP version" code_2xx
  api cu PUT '/api/v1/user/domains/{id}' "/api/v1/user/domains/$CDID" '{"php_version":"4.4"}'; check php "unknown PHP version refused" code_4xx
}

s_cron() {
  api cu POST /api/v1/user/cron /api/v1/user/cron '{"minute":"*/5","hour":"*","dom":"*","month":"*","dow":"*","command":"echo core-cron >/dev/null"}'; check cron "add cron job" code_2xx
  check cron "installed in the account's crontab" bash -c "crontab -l -u $C | grep -q core-cron"
  api cu GET /api/v1/user/cron /api/v1/user/cron; local id; id=$(echo "$BODY" | jq -r '[.. | objects | select((.command? // "") | test("core-cron"))][0].id')
  api cu POST /api/v1/user/cron /api/v1/user/cron '{"minute":"61","hour":"*","dom":"*","month":"*","dow":"*","command":"x"}'; check cron "invalid schedule refused" code_4xx
  api cu DELETE '/api/v1/user/cron/{id}' "/api/v1/user/cron/$id"; check cron "delete cron job" code_2xx
  check cron "removed from crontab" bash -c "! crontab -l -u $C 2>/dev/null | grep -q core-cron"
}

s_security() {
  local NP="CoreNew${RANDOM}w8"
  api cu POST /api/v1/account/password /api/v1/account/password "$(jq -nc --arg c "$CPASS" --arg n "$NP" '{current:$c,new:$n}')"; check password "change own password" code_2xx
  CPASS=$NP; save CPASS
  ROLE_OF_SESSION=user login cu user "$C" "$CPASS"; check password "login with the new password" code_is 200
  creauth; api cu POST /api/v1/account/totp/setup /api/v1/account/totp/setup; check 2fa "TOTP setup (secret + otpauth URL)" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -q otpauth"; local sec; sec=$(jqb '.secret')
  api cu POST /api/v1/account/totp/enable /api/v1/account/totp/enable "{\"code\":\"$(totp_now "$sec")\"}"; check 2fa "enable TOTP" code_2xx; echo "$BODY" | jq 'del(.recovery_codes)' 2>/dev/null | ev core-totp-enable.json
  ROLE_OF_SESSION=user login cu2 user "$C" "$CPASS"; check 2fa "login without a code is refused" bash -c "[ $CODE != 200 ] || ! echo '$BODY' | jq -e .csrf >/dev/null"
  # a TOTP code is accepted once (replay protection): wait for the next 30 s window each time
  next_window; ROLE_OF_SESSION=user login cu user "$C" "$CPASS" "$(totp_now "$sec")"; check 2fa "login with the TOTP code" code_is 200
  next_window; api cu POST /api/v1/account/totp/disable /api/v1/account/totp/disable "{\"code\":\"$(totp_now "$sec")\"}"; check 2fa "disable TOTP" code_2xx
  api cu GET /api/v1/account/sessions /api/v1/account/sessions; check sessions "list own sessions" code_is 200
}

s_prefs() {
  api cu PUT /api/v1/account/preferences /api/v1/account/preferences '{"lang":"tr","theme":"dark"}'; check prefs "set language TR + dark theme" code_2xx
  api cu GET /api/v1/auth/me /api/v1/auth/me; check prefs "persisted (auth/me)" bash -c "echo '$BODY' | grep -q '\"tr\"'"
  api cu PUT /api/v1/account/preferences /api/v1/account/preferences '{"lang":"xx"}'; check prefs "unknown language refused" code_4xx
  api cu PUT /api/v1/account/preferences /api/v1/account/preferences '{"lang":"en","theme":"light"}'
}

s_admin() {
  api admin GET /api/v1/admin/server /api/v1/admin/server; check server-info "server information" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -qi 'ubuntu\\|kernel'"; echo "$BODY" | ev core-server.json
  api admin GET /api/v1/admin/settings /api/v1/admin/settings; check basic-setup "server settings" code_is 200; echo "$BODY" | ev core-settings.json
  local ns; ns=$(echo "$BODY" | jq -c '.nameservers // .settings.nameservers // ["ns1.e2e.test","ns2.e2e.test"]')
  api admin PUT /api/v1/admin/settings /api/v1/admin/settings "$(echo "$BODY" | jq -c --argjson ns "$ns" '(.settings // .) | {nameservers:$ns, contact_email:"ops@e2e.test", default_lang:(.default_lang // "en")}')"; check basic-setup "update settings (contact e-mail, nameservers)" code_2xx
  api admin GET /api/v1/admin/settings /api/v1/admin/settings; check basic-setup "settings persisted" bash -c "echo '$BODY' | grep -q ops@e2e.test"
  api admin GET /api/v1/admin/audit "/api/v1/admin/audit?q=$C&limit=50"; check audit "audit trail records the account's actions" bash -c "echo '$BODY' | grep -q 'account.create\\|account\\.create'"; echo "$BODY" | head -c 4000 | ev core-audit.json
  api admin GET /api/v1/admin/accounts "/api/v1/admin/accounts?q=$C"; check accounts "list/search accounts" bash -c "echo '$BODY' | grep -q '\"$C\"'"
}

s_services() {
  api admin GET /api/v1/admin/services /api/v1/admin/services; check services "service status" code_is 200; echo "$BODY" | ev core-services.json
  reauth; api admin POST '/api/v1/admin/services/{unit}/{action}' /api/v1/admin/services/pure-ftpd/restart; check services "restart a service (pure-ftpd)" code_2xx
  check services "service active again" bash -c "sleep 2; systemctl is-active pure-ftpd"
  reauth; api admin POST '/api/v1/admin/services/{unit}/{action}' /api/v1/admin/services/bpanel-agent/stop; check services "critical unit cannot be stopped" code_4xx
}

s_lifecycle() {
  check suspend "mail login works before suspend (control)" bash -c "curl -s -m 20 --noproxy '*' -k --url imaps://127.0.0.1/ --user 'user1@$CDOM:$CMP' -X 'LIST \"\" \"*\"' | grep -qi inbox"
  reauth; api admin POST '/api/v1/admin/accounts/{id}/suspend' "/api/v1/admin/accounts/$CID/suspend" '{"reason":"e2e"}'; check suspend "suspend account" code_2xx
  check suspend "site shows the suspended page" bash -c "sleep 2; ! web $CDOM -L http://$CDOM/ | grep -q 'main $BP_TAG'"
  ROLE_OF_SESSION=user login cu3 user "$C" "$CPASS"; check suspend "suspended user cannot log in" bash -c "[ $CODE != 200 ]"
  check suspend "mail login (IMAP) refused while suspended" bash -c "sleep 2; ! curl -s -m 20 --noproxy '*' -k --url imaps://127.0.0.1/ --user 'user1@$CDOM:$CMP' -X 'LIST \"\" \"*\"' | grep -qi inbox"
  check suspend "SMTP AUTH refused while suspended" bash -c "! curl -s -m 20 --noproxy '*' -k --ssl-reqd --url smtp://127.0.0.1:587/ --user 'user1@$CDOM:$CMP' --mail-from 'user1@$CDOM' --mail-rcpt 'user1@$CDOM' -T /dev/null"
  reauth; api admin POST '/api/v1/admin/accounts/{id}/unsuspend' "/api/v1/admin/accounts/$CID/unsuspend"; check suspend "unsuspend" code_2xx
  check suspend "site back" bash -c "sleep 2; web $CDOM -L http://$CDOM/ | grep -q 'main $BP_TAG'"
  check suspend "mail login works again after unsuspend" bash -c "sleep 2; curl -s -m 20 --noproxy '*' -k --url imaps://127.0.0.1/ --user 'user1@$CDOM:$CMP' -X 'LIST \"\" \"*\"' | grep -qi inbox"
  local NP="AdminSet${RANDOM}p2"
  reauth; api admin POST '/api/v1/admin/accounts/{id}/password' "/api/v1/admin/accounts/$CID/password" "$(jq -nc --arg p "$NP" '{password:$p}')"; check accounts "admin sets the account password" code_2xx
  ROLE_OF_SESSION=user login cu user "$C" "$NP"; check accounts "user logs in with it" code_is 200; CPASS=$NP; save CPASS
  api admin PUT '/api/v1/admin/accounts/{id}/package' "/api/v1/admin/accounts/$CID/package" "{\"package_id\":$PKG}"; check accounts "change package" code_2xx
  reauth; api admin POST '/api/v1/admin/accounts/{id}/login' "/api/v1/admin/accounts/$CID/login"; check accounts "admin login-as (one-time link)" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -q 'http'"
  reauth; api admin DELETE '/api/v1/admin/accounts/{id}' "/api/v1/admin/accounts/$CID"; check terminate "terminate account" code_2xx
  check terminate "system user, home, vhost, zone, mailboxes and databases removed" bash -c "sleep 3; ! id $C 2>/dev/null && [ ! -d $CH ] && ! ls /etc/nginx/bpanel.d/ | grep -q '$CDOM' && [ -z \"\$(dig +short @127.0.0.1 $CDOM SOA)\" ] && ! mysql -N -e 'SHOW DATABASES' | grep -q '^${C}_'"
  api admin DELETE '/api/v1/admin/packages/{id}' "/api/v1/admin/packages/$CPKG"; check packages "delete unused package" code_2xx
}

s_api() {
  local bv; bv=$(bpanel-api --version 2>/dev/null | awk '{print $2}')
  check api-docs "OpenAPI document served (v$bv, the installed build)" bash -c "curl -sk -m 20 --noproxy '*' $ADMIN_URL/openapi.json | jq -e '.info.version == \"$bv\" and (.paths | length) > 250' >/dev/null || curl -sk -m 20 --noproxy '*' $ADMIN_URL/api/v1/openapi.json | jq -e '.info.version == \"$bv\"' >/dev/null"
}

for s in "${SECTIONS[@]}"; do echo "== $s"; "s_$s"; done
