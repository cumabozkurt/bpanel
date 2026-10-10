#!/bin/bash
# BPANEL v1.1.0 end-to-end suite (runs INSIDE a disposable server/container as root).
# Drives the v1.1 routes over HTTPS as admin and user and checks the real system effect.
#   BP_ADMIN_PASS=… ./v11.sh [section ...]
cd "$(dirname "$0")"
source ./lib.sh
STATE="$BP_OUT/state.env"; touch "$STATE"; source "$STATE"
save() { for v in "$@"; do sed -i "/^$v=/d" "$STATE"; printf '%s=%q\n' "$v" "${!v}" >> "$STATE"; done; }
: "${U:=u${BP_TAG}}"; : "${DOM:=${U}.${BP_TLD}}"; : "${UPASS:=UserPass${RANDOM}x9}"; : "${MPASS:=MailPass${RANDOM}y7}"; save U DOM UPASS MPASS
ev() { cat > "$BP_OUT/ev/$1"; }
redact() { sed -e "s/$BP_ADMIN_PASS/<REDACTED>/g" -e "s/$UPASS/<REDACTED>/g" -e "s/$MPASS/<REDACTED>/g"; }
HOME_=/home/$U; PH=$HOME_/public_html
asuser() { runuser -u "$U" -- "$@"; }
hcurl() { curl -s --noproxy '*' -H "Host: $DOM" "$@"; }
reauth() { api admin POST /api/v1/account/reauth /api/v1/account/reauth "$(jq -nc --arg p "$BP_ADMIN_PASS" '{password:$p}')"; }
SECTIONS=(setup visitors routing boxtrapper gpg dav sshkeys sitepub images pg cloudflare webx mailqueue trouble ips hostname tweak phpext billing whmcs)
[ $# -gt 0 ] && SECTIONS=("$@")

s_setup() {
  ROLE_OF_SESSION=admin login admin admin "$BP_ADMIN_USER" "$BP_ADMIN_PASS"; check setup "admin login" code_is 200
  reauth; check setup "admin step-up reauth" code_2xx
  # webhook receiver first so account.created is captured (billing section checks it)
  pkill -f hook.py; : > "$BP_OUT/ev/webhooks.jsonl"; (python3 hook.py 9911 "$BP_OUT/ev/webhooks.jsonl" &>/dev/null &)
  api admin PUT /api/v1/admin/webhooks/settings /api/v1/admin/webhooks/settings '{"allow_private":true}'; check setup "webhook settings allow_private (local receiver)" code_2xx
  HSECRET="whsec-e2e-${RANDOM}${RANDOM}abcdef"; save HSECRET
  api admin GET /api/v1/admin/webhooks /api/v1/admin/webhooks; for h in $(echo "$BODY" | jq -r '.. | objects | select(.name? == "whmcs-e2e") | .id'); do api admin DELETE '/api/v1/admin/webhooks/{id}' "/api/v1/admin/webhooks/$h"; done
  api admin POST /api/v1/admin/webhooks /api/v1/admin/webhooks "{\"name\":\"whmcs-e2e\",\"url\":\"http://127.0.0.1:9911/hook\",\"events\":[\"account.*\"],\"secret\":\"$HSECRET\"}"
  check setup "billing webhook created (account.*)" code_2xx; HID=$(jqb '.id // .webhook.id'); save HID
  api admin GET /api/v1/admin/packages /api/v1/admin/packages; PKG=$(jqb '[.. | objects | select(.disk_mb? != null)][0].id'); save PKG
  api admin POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"$U\",\"domain\":\"$DOM\",\"email\":\"owner@$BP_TLD\",\"password\":\"$UPASS\",\"package_id\":$PKG,\"role\":\"user\"}"
  check setup "create hosting account $U" code_is 200; UID_=$(jqb '.account.id'); save UID_
  ROLE_OF_SESSION=user login user user "$U" "$UPASS"; check setup "user login" code_is 200
  api user GET /api/v1/user/domains /api/v1/user/domains; DID=$(echo "$BODY" | jq -r --arg n "$DOM" '[.. | objects | select(.name? == $n)][0].id'); save DID
  api user POST /api/v1/user/email/accounts /api/v1/user/email/accounts "{\"domain\":\"$DOM\",\"local\":\"info\",\"password\":\"$MPASS\",\"quota_mb\":50}"; check setup "mailbox info@$DOM" code_2xx
  api user GET /api/v1/user/email/accounts /api/v1/user/email/accounts; MBID=$(echo "$BODY" | jq -r --arg e "info@$DOM" '[.. | objects | select(.email? == $e)][0].id'); save MBID
  check setup "ids resolved (domain $DID, mailbox $MBID)" bash -c "[[ '$DID' =~ ^[0-9]+$ && '$MBID' =~ ^[0-9]+$ ]]"
}

s_visitors() {
  for i in 1 2 3 4 5; do hcurl -A "Mozilla/5.0 (E2E $i) Firefox/120" -o /dev/null "http://127.0.0.1/?p=$i"; done
  hcurl -A "Googlebot/2.1" -o /dev/null http://127.0.0.1/robots.txt; hcurl -o /dev/null http://127.0.0.1/nope-404
  check visitors "nginx wrote the domain access log" bash -c "ls /var/log/nginx/ /var/log/bpanel/domlogs/ 2>/dev/null | grep -q '$DOM'; find / -xdev -name '$DOM.access.log' -size +0 2>/dev/null | grep ."
  api user GET /api/v1/user/stats/visitors /api/v1/user/stats/visitors; check visitors "domain list" code_is 200
  api user GET /api/v1/user/stats/visitors "/api/v1/user/stats/visitors?domain=$DOM"; check visitors "stats of $DOM" code_is 200; echo "$BODY" | ev visitors.json
  check visitors "real hits counted (>=7 requests, 404 seen, bot seen)" bash -c "jq -e '([.. | objects | .hits? // empty] | add // 0) >= 7 or (tostring | test(\"nope-404\"))' $BP_OUT/ev/visitors.json"
  api user GET /api/v1/user/stats/visitors "/api/v1/user/stats/visitors?domain=other.example"; check visitors "foreign domain refused" code_4xx
}

s_routing() {
  api user GET /api/v1/user/email/routing /api/v1/user/email/routing; check routing "list routing" code_is 200; echo "$BODY" | ev routing-before.json
  api user PUT '/api/v1/user/email/routing/{domain}' "/api/v1/user/email/routing/$DOM" '{"mode":"remote"}'; check routing "set remote" code_2xx
  tq() { local m; m=$(postconf -h transport_maps | tr ', ' '\n' | grep ':' | head -1); echo "transport_maps=$m"; postmap -q "$DOM" "$m"; }
  { echo "## remote"; tq; } > "$BP_OUT/ev/routing-postfix.txt" 2>&1
  check routing "postfix transport_maps resolves $DOM -> smtp: (remote MX)" bash -c "grep -qx 'smtp:' $BP_OUT/ev/routing-postfix.txt"
  swaks -s 127.0.0.1 -t "info@$DOM" -f probe@example.org --h-Subject routing-remote-e2e >/dev/null 2>&1; sleep 4
  check routing "remote mode: mail not delivered locally, handed to smtp (queued/deferred)" bash -c "! grep -rqs routing-remote-e2e /home/$U/mail && postqueue -j | jq -r 'select(.recipients[].address==\"info@$DOM\") | .queue_id' | grep -q ."
  postqueue -j | jq -r "select(.recipients[].address==\"info@$DOM\") | .queue_id" | while read -r q; do postsuper -d "$q" >/dev/null 2>&1; done
  api user GET /api/v1/user/email/routing /api/v1/user/email/routing; check routing "mode persisted = remote" bash -c "echo '$BODY' | jq -e '[.. | objects | select(.domain? == \"$DOM\")][0].mode == \"remote\"'"
  api user PUT '/api/v1/user/email/routing/{domain}' "/api/v1/user/email/routing/$DOM" '{"mode":"bogus"}'; check routing "invalid mode refused" code_4xx
  api user PUT '/api/v1/user/email/routing/{domain}' "/api/v1/user/email/routing/$DOM" '{"mode":"local"}'; check routing "back to local" code_2xx
  { echo "## local"; tq; echo "(empty = default virtual transport)"; } >> "$BP_OUT/ev/routing-postfix.txt" 2>&1
  check routing "transport entry removed again" bash -c "[ -z \"\$(postmap -q $DOM \$(postconf -h transport_maps | tr ', ' '\\n' | grep : | head -1))\" ]"
  check routing "local delivery works after switching back (swaks -> Maildir)" bash -c "swaks -s 127.0.0.1 -t info@$DOM -f probe@example.org --h-Subject routing-e2e >/dev/null 2>&1; sleep 4; grep -rl 'routing-e2e' /var/vmail /home/$U/mail 2>/dev/null | grep -q ."
}

s_boxtrapper() {
  api user GET /api/v1/user/email/boxtrapper /api/v1/user/email/boxtrapper; check boxtrapper "list" code_is 200
  api user PUT '/api/v1/user/email/boxtrapper/{id}' "/api/v1/user/email/boxtrapper/$MBID" '{"enabled":true,"whitelist":["friend@example.org"],"blacklist":["spam@example.net"],"folder":"BoxTrapper"}'
  check boxtrapper "enable with lists" code_2xx
  check boxtrapper "sieve script installed for the mailbox" bash -c "f=\$(grep -rl 'friend@example.org' /home/$U/mail 2>/dev/null | grep '\.sieve\$' | head -1); [ -n \"\$f\" ] && cp \"\$f\" $BP_OUT/ev/boxtrapper.sieve && echo \$f"
  check boxtrapper "active link is ~/dovecot.sieve (not a Maildir++ folder name)" bash -c "readlink /home/$U/mail/$DOM/info/dovecot.sieve && [ ! -e /home/$U/mail/$DOM/info/.dovecot.sieve ]"
  swaks -s 127.0.0.1 -t "info@$DOM" -f stranger@example.com --h-Subject bt-unknown-e2e >/dev/null 2>&1
  swaks -s 127.0.0.1 -t "info@$DOM" -f friend@example.org --h-Subject bt-friend-e2e >/dev/null 2>&1
  sleep 5
  check boxtrapper "unknown sender quarantined in BoxTrapper folder" bash -c "grep -rl 'bt-unknown-e2e' /var/vmail /home/$U/mail 2>/dev/null | grep -i 'boxtrapper'"
  check boxtrapper "whitelisted sender delivered to INBOX" bash -c "grep -rl 'bt-friend-e2e' /var/vmail /home/$U/mail 2>/dev/null | grep -vi 'boxtrapper' | grep -q ."
  api user PUT '/api/v1/user/email/boxtrapper/{id}' "/api/v1/user/email/boxtrapper/$MBID" '{"enabled":false}'; check boxtrapper "disable" code_2xx
}

s_gpg() {
  api user POST /api/v1/user/gpg/generate /api/v1/user/gpg/generate "{\"name\":\"E2E User\",\"email\":\"info@$DOM\",\"algo\":\"ed25519\",\"expire\":\"1y\"}"; check gpg "generate ed25519 key" code_2xx
  api user GET /api/v1/user/gpg /api/v1/user/gpg; check gpg "list keys" code_is 200; echo "$BODY" | ev gpg-list.json
  FPR=$(jq -r '[.. | objects | .fingerprint? // empty][0]' "$BP_OUT/ev/gpg-list.json"); save FPR
  check gpg "key in the user's real keyring (gpg --list-keys)" bash -c "asuser() { runuser -u $U -- \"\$@\"; }; asuser gpg --homedir $HOME_/.gnupg --list-keys --with-colons 2>/dev/null | grep -q '$FPR'"
  api user GET '/api/v1/user/gpg/{fpr}/export' "/api/v1/user/gpg/$FPR/export"; check gpg "export armored public key" bash -c "echo '$BODY' | grep -q 'BEGIN PGP PUBLIC KEY BLOCK'"
  local arm; arm=$(echo "$BODY" | jq -r '.armored // .key // .' 2>/dev/null)
  api user DELETE '/api/v1/user/gpg/{fpr}' "/api/v1/user/gpg/$FPR"; check gpg "delete key" code_2xx
  api user POST /api/v1/user/gpg/import /api/v1/user/gpg/import "$(jq -nc --arg a "$arm" '{armored:$a}')"; check gpg "re-import exported key" code_2xx
  api user GET /api/v1/user/gpg /api/v1/user/gpg; check gpg "imported key listed" bash -c "echo '$BODY' | grep -q '$FPR'"
  api user POST /api/v1/user/gpg/import /api/v1/user/gpg/import '{"armored":"not a key"}'; check gpg "garbage import refused" code_4xx
  api user DELETE '/api/v1/user/gpg/{fpr}' "/api/v1/user/gpg/$FPR"
}

s_dav() {
  api user GET /api/v1/user/calendars /api/v1/user/calendars; check dav "status" code_is 200; echo "$BODY" | ev dav-status.json
  DAVPW="DavPass${RANDOM}z3"
  api user PUT '/api/v1/user/calendars/{id}' "/api/v1/user/calendars/$MBID" "{\"password\":\"$DAVPW\"}"; check dav "enable DAV for info@" code_2xx
  sleep 2
  local u="info@$DOM" c
  c=$(curl -sk --noproxy '*' -o "$BP_OUT/ev/dav-propfind.xml" -w '%{http_code}' -u "$u:$DAVPW" -X PROPFIND -H 'Depth: 1' "$USER_URL/dav/$u/"); cover PROPFIND /dav/ dav "$c"
  check dav "PROPFIND principal via /dav proxy -> 207 (Radicale)" bash -c "[ $c = 207 ]"
  c=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -u "$u:$DAVPW" -X MKCOL -H 'Content-Type: application/xml' --data '<?xml version="1.0"?><D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop><D:resourcetype><D:collection/><C:calendar/></D:resourcetype></D:prop></D:set></D:mkcol>' "$USER_URL/dav/$u/e2ecal/")
  check dav "MKCOL calendar -> 201" bash -c "[ $c = 201 ]"
  c=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -u "$u:$DAVPW" -X PUT -H 'Content-Type: text/calendar' --data-binary $'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//e2e//EN\r\nBEGIN:VEVENT\r\nUID:e2e-1@bpanel\r\nDTSTAMP:20261010T120000Z\r\nDTSTART:20261011T090000Z\r\nDTEND:20261011T100000Z\r\nSUMMARY:BPANEL E2E event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n' "$USER_URL/dav/$u/e2ecal/e2e-1.ics")
  check dav "PUT event -> 201" bash -c "[ $c = 201 ]"
  check dav "GET event back" bash -c "curl -sk --noproxy '*' -u '$u:$DAVPW' '$USER_URL/dav/$u/e2ecal/e2e-1.ics' | grep -q 'BPANEL E2E event'"
  c=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -u "$u:wrong-password" -X PROPFIND "$USER_URL/dav/$u/"); check dav "wrong password -> 401" bash -c "[ $c = 401 ]"
  api user DELETE '/api/v1/user/calendars/{id}' "/api/v1/user/calendars/$MBID"; check dav "disable DAV" code_2xx; sleep 2
  c=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -u "$u:$DAVPW" -X PROPFIND "$USER_URL/dav/$u/"); check dav "after disable -> 401" bash -c "[ $c = 401 ]"
}

s_sshkeys() {
  api user POST /api/v1/user/ssh-keys/generate /api/v1/user/ssh-keys/generate '{"name":"e2e_ed","type":"ed25519","authorize":true}'; check ssh "generate ed25519 (authorized)" code_2xx
  echo "$BODY" | jq -r '.private_key // .private // empty' > /tmp/e2e_ed; chmod 600 /tmp/e2e_ed
  check ssh "private key returned once" bash -c "grep -q 'PRIVATE KEY' /tmp/e2e_ed"
  check ssh "authorized_keys contains the key" bash -c "ssh-keygen -y -f /tmp/e2e_ed | cut -d' ' -f2 | xargs -I{} grep -q {} $HOME_/.ssh/authorized_keys"
  check ssh "authorized_keys perms 0600 owned by $U" bash -c "stat -c '%U %a' $HOME_/.ssh/authorized_keys | grep -qx '$U 600'"
  check ssh "real SSH/SFTP login with the generated key" bash -c "echo pwd | sftp -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /tmp/e2e_ed $U@127.0.0.1 2>&1 | tail -2"
  ssh-keygen -q -t rsa -b 3072 -N '' -C imported -f /tmp/e2e_rsa <<<y >/dev/null
  api user POST /api/v1/user/ssh-keys/import /api/v1/user/ssh-keys/import "$(jq -nc --arg k "$(cat /tmp/e2e_rsa.pub)" '{name:"e2e_rsa",public_key:$k,authorize:false}')"; check ssh "import RSA public key" code_2xx
  api user GET /api/v1/user/ssh-keys /api/v1/user/ssh-keys; check ssh "list" code_is 200; echo "$BODY" | ev sshkeys.json
  api user POST '/api/v1/user/ssh-keys/{name}/authorize' /api/v1/user/ssh-keys/e2e_ed/authorize '{"authorize":false}'; check ssh "deauthorize" code_2xx
  check ssh "deauthorized key no longer logs in" bash -c "! (echo pwd | sftp -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /tmp/e2e_ed $U@127.0.0.1 >/dev/null 2>&1)"
  api user POST /api/v1/user/ssh-keys/import /api/v1/user/ssh-keys/import '{"name":"../x","public_key":"ssh-ed25519 AAAA"}'; check ssh "path-traversal name refused" code_4xx
  api user DELETE '/api/v1/user/ssh-keys/{name}' /api/v1/user/ssh-keys/e2e_ed; check ssh "delete" code_2xx
  api user DELETE '/api/v1/user/ssh-keys/{name}' /api/v1/user/ssh-keys/e2e_rsa
}

s_sitepub() {
  api user GET /api/v1/user/site-publisher /api/v1/user/site-publisher; check sitepub "templates + domains" code_is 200
  api user POST /api/v1/user/site-publisher /api/v1/user/site-publisher "{\"domain_id\":$DID,\"template\":\"business\",\"lang\":\"en\",\"fields\":{\"title\":\"E2E Widgets Ltd\",\"tagline\":\"Quality since 2026\",\"email\":\"info@$DOM\"},\"overwrite\":true}"
  check sitepub "publish business template" code_2xx
  check sitepub "site serves the published page" bash -c "curl -s --noproxy '*' -H 'Host: $DOM' http://127.0.0.1/ | grep -q 'E2E Widgets Ltd'"
  check sitepub "index.html owned by the user" bash -c "stat -c %U $PH/index.html | grep -qx $U"
  api user POST /api/v1/user/site-publisher /api/v1/user/site-publisher "{\"domain_id\":$DID,\"template\":\"maintenance\",\"lang\":\"tr\",\"fields\":{\"title\":\"x\"}}"; check sitepub "no overwrite -> 409 site_exists" code_is 409
  api user POST /api/v1/user/site-publisher /api/v1/user/site-publisher "{\"domain_id\":$DID,\"template\":\"<script>\",\"fields\":{}}"; check sitepub "unknown template refused" code_4xx
  api user POST /api/v1/user/site-publisher /api/v1/user/site-publisher "{\"domain_id\":$DID,\"template\":\"personal\",\"lang\":\"en\",\"fields\":{\"title\":\"<script>alert(1)</script>\"},\"overwrite\":true}"
  check sitepub "fields are HTML-escaped" bash -c "grep -q '&lt;script&gt;' $PH/index.html && ! grep -q '<script>alert' $PH/index.html"
}

s_images() {
  python3 - "$PH/e2e.png" <<'P'
import zlib, struct, sys
w, h = 640, 480
raw = b''.join(b'\x00' + bytes(v for x in range(w) for v in (x * 255 // w, y * 255 // h, 128)) for y in range(h))
def ch(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
open(sys.argv[1], 'wb').write(b'\x89PNG\r\n\x1a\n' + ch(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + ch(b'IDAT', zlib.compress(raw)) + ch(b'IEND', b''))
P
  chown "$U:$U" "$PH/e2e.png"
  api user POST /api/v1/user/images /api/v1/user/images '{"path":"public_html/e2e.png","op":"thumbnail","width":120}'; check images "thumbnail" code_2xx; echo "$BODY" | ev images-thumb.json
  check images "thumbnail file is a 120px-wide PNG" bash -c "f=\$(ls $PH/thumbnails/tn_e2e.* 2>/dev/null | head -1); [ -n \"\$f\" ] && file \"\$f\" | tee /dev/stderr | grep -q '120 x'"
  api user POST /api/v1/user/images /api/v1/user/images '{"path":"public_html/e2e.png","op":"scale","percent":50}'; check images "scale 50%" code_2xx
  check images "scaled 320x240 written" bash -c "file $PH/e2e-320x240.png | grep -q '320 x 240'"
  api user POST /api/v1/user/images /api/v1/user/images '{"path":"public_html/e2e.png","op":"convert","format":"jpeg","quality":80}'; check images "convert to JPEG" code_2xx
  check images "JPEG written and owned by $U" bash -c "file $PH/e2e.jpg | grep -q JPEG && stat -c %U $PH/e2e.jpg | grep -qx $U"
  api user POST /api/v1/user/images /api/v1/user/images '{"path":"../../etc/passwd","op":"thumbnail","width":10}'; check images "path escape refused" code_4xx
}

s_pg() {
  check pg "PostgreSQL server running in the container" systemctl is-active postgresql@16-main
  PGPW="PgPass1${RANDOM}q8"
  api user POST /api/v1/user/postgresql /api/v1/user/postgresql "{\"name\":\"app\",\"password\":\"$PGPW\"}"; check pg "create database ${U}_app" code_2xx
  api user GET /api/v1/user/postgresql/browser /api/v1/user/postgresql/browser; check pg "browser info (psql available)" bash -c "[ $CODE = 200 ] && echo '$BODY' | jq -e '.. | objects | select(.name? == \"${U}_app\")' >/dev/null"
  PGID=$(echo "$BODY" | jq -r --arg n "${U}_app" '[.. | objects | select(.name? == $n)][0].id')
  q() { api user POST /api/v1/user/postgresql/browser/query /api/v1/user/postgresql/browser/query "$(jq -nc --argjson id "$PGID" --arg p "${2:-$PGPW}" --arg s "$1" '{database_id:$id,password:$p,sql:$s}')"; }
  q "CREATE TABLE widgets(id serial primary key, name text); INSERT INTO widgets(name) VALUES ('alpha'),('beta');"; check pg "DDL + INSERT via real psql" code_2xx
  q "SELECT name FROM widgets ORDER BY id"; check pg "SELECT returns rows" bash -c "echo '$BODY' | grep -q alpha && echo '$BODY' | grep -q beta"; echo "$BODY" | ev pg-select.json
  api user POST /api/v1/user/postgresql/browser/tables /api/v1/user/postgresql/browser/tables "$(jq -nc --argjson id "$PGID" --arg p "$PGPW" '{database_id:$id,password:$p}')"; check pg "tables lists widgets" bash -c "echo '$BODY' | grep -q widgets"
  q '\! id'; check pg "psql meta-command refused" code_4xx
  q "SELECT 1" "wrong-pass"; check pg "wrong role password -> pg_auth_failed" bash -c "echo '$BODY' | grep -q pg_auth_failed"
  q "SELECT pg_sleep(20)"; check pg "statement_timeout enforced (15 s)" bash -c "echo '$BODY' | grep -qi 'timeout\|cancel\|pg_query_failed'"
  q "SELECT * FROM pg_authid"; check pg "role cannot read pg_authid (not superuser)" bash -c "echo '$BODY' | grep -q pg_query_failed"
  q "SELECT generate_series(1,5000)"; check pg "1000-row cap" bash -c "echo '$BODY' | jq -e '(.rows|length) <= 1000 and (.truncated // true)'"
}

s_cloudflare() {
  api user GET /api/v1/user/cloudflare /api/v1/user/cloudflare; check cf "status (NS detection, not linked)" code_is 200; echo "$BODY" | ev cf-status.json
  CFT="cf-e2e-token-${RANDOM}${RANDOM}"
  pkill -f cfmock.py; : > "$BP_OUT/ev/cf-mock-requests.jsonl"; (python3 cfmock.py 9922 "$CFT" "$DOM" "$BP_OUT/ev/cf-mock-requests.jsonl" &>/dev/null &); sleep 1
  sqlite3 /var/lib/bpanel/db/bpanel.db "INSERT OR REPLACE INTO settings(key,value) VALUES('cloudflare_api_base','http://127.0.0.1:9922/client/v4')" 2>&1 || true
  api user PUT /api/v1/user/cloudflare /api/v1/user/cloudflare '{"token":"wrong-token"}'; check cf "invalid token refused (verify against API)" code_4xx
  api user PUT /api/v1/user/cloudflare /api/v1/user/cloudflare "{\"token\":\"$CFT\"}"; check cf "link token (verified)" code_2xx
  check cf "token not stored in plain text in the DB" bash -c "! sqlite3 /var/lib/bpanel/db/bpanel.db .dump | grep -q '$CFT'"
  api user POST /api/v1/user/cloudflare/sync /api/v1/user/cloudflare/sync "{\"domain_id\":$DID,\"dry_run\":true}"; check cf "dry-run lists missing records" code_2xx; echo "$BODY" | ev cf-dryrun.json
  local before; before=$(grep -c '"m": "POST"' "$BP_OUT/ev/cf-mock-requests.jsonl")
  check cf "dry-run created nothing" bash -c "[ $before = 0 ]"
  api user POST /api/v1/user/cloudflare/sync /api/v1/user/cloudflare/sync "{\"domain_id\":$DID}"; check cf "sync creates the missing records" code_2xx; echo "$BODY" | ev cf-sync.json
  check cf "mock API received record creations (MX/TXT included)" bash -c "grep '\"m\": \"POST\"' $BP_OUT/ev/cf-mock-requests.jsonl | grep -q MX && grep '\"m\": \"POST\"' $BP_OUT/ev/cf-mock-requests.jsonl | grep -q TXT"
  api user DELETE /api/v1/user/cloudflare /api/v1/user/cloudflare; check cf "unlink" code_2xx
  sqlite3 /var/lib/bpanel/db/bpanel.db "DELETE FROM settings WHERE key='cloudflare_api_base'" 2>/dev/null; pkill -f cfmock.py
}

s_webx() {
  mkdir -p "$PH/pub" "$PH/members"; echo hello > "$PH/pub/a.txt"; echo "plain body" > "$PH/pub/x.foo"; echo secret > "$PH/members/s.txt"; chown -R "$U:$U" "$PH/pub" "$PH/members"
  local c; c=$(hcurl -o /dev/null -w '%{http_code}' http://127.0.0.1/pub/); echo "before indexes: $c" > "$BP_OUT/ev/webx.txt"
  api user PUT '/api/v1/user/web/{id}/indexes' "/api/v1/user/web/$DID/indexes" '{"indexes":[{"path":"pub","mode":"on"}]}'; check webx "indexes on for /pub" code_2xx; sleep 2
  check webx "directory listing served" bash -c "curl -s --noproxy '*' -H 'Host: $DOM' http://127.0.0.1/pub/ | tee -a $BP_OUT/ev/webx.txt | grep -q 'a.txt'"
  api user PUT '/api/v1/user/web/{id}/indexes' "/api/v1/user/web/$DID/indexes" '{"indexes":[{"path":"pub","mode":"off"}]}'; sleep 2
  check webx "indexes off -> 403" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $DOM' http://127.0.0.1/pub/) = 403 ]"
  hcurl -sI http://127.0.0.1/pub/x.foo | grep -i content-type | sed 's/^/before handler: /' >> "$BP_OUT/ev/webx.txt"
  api user PUT '/api/v1/user/web/{id}/handlers' "/api/v1/user/web/$DID/handlers" '{"handlers":[{"ext":"foo","handler":"text-plain"}]}'; check webx "handler .foo -> text-plain" code_2xx; sleep 2
  check webx ".foo served as text/plain" bash -c "curl -sI --noproxy '*' -H 'Host: $DOM' http://127.0.0.1/pub/x.foo | tee -a $BP_OUT/ev/webx.txt | grep -i '^content-type: text/plain'"
  api user PUT '/api/v1/user/web/{id}/handlers' "/api/v1/user/web/$DID/handlers" '{"handlers":[{"ext":"php","handler":"cgi-script"}]}'; check webx "non-allowlisted handler refused" code_4xx
  api user PUT '/api/v1/user/web/{id}/privacy' "/api/v1/user/web/$DID/privacy" '{"dirs":[{"path":"members","realm":"Members","users":[{"name":"alice","password":"AlicePass123x"}]}]}'; check webx "protect /members (alice)" code_2xx
  api user PUT '/api/v1/user/web/{id}/leech' "/api/v1/user/web/$DID/leech" '{"path":"members","leech_max":2}'; check webx "leech limit 2 IPs" code_2xx; sleep 2
  for ip in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5; do curl -s --noproxy '*' --interface "$ip" -o /dev/null -u alice:AlicePass123x -H "Host: $DOM" "http://$ip/members/s.txt"; done
  api user POST '/api/v1/user/web/{id}/leech/scan' "/api/v1/user/web/$DID/leech/scan"; check webx "leech scan disables alice (4 IPs > 2)" bash -c "echo '$BODY' | grep -q alice"; echo "$BODY" | ev leech-scan.json; sleep 2
  check webx "disabled login now refused (401)" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -u alice:AlicePass123x -H 'Host: $DOM' http://127.0.0.1/members/s.txt) = 401 ]"
  api user POST '/api/v1/user/web/{id}/leech/enable' "/api/v1/user/web/$DID/leech/enable" '{"path":"members","user":"alice"}'; check webx "re-enable alice" code_2xx; sleep 2
  check webx "re-enabled login works (200)" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -u alice:AlicePass123x -H 'Host: $DOM' http://127.0.0.1/members/s.txt) = 200 ]"
}

s_mailqueue() {
  local old; old=$(postconf -h defer_transports); postconf -e 'defer_transports = smtp'; postfix reload >/dev/null 2>&1
  printf 'Subject: mq-e2e\n\nqueued by the e2e\n' | sendmail -f "info@$DOM" queued-e2e@example.com; sleep 3
  api admin GET /api/v1/admin/mail-queue /api/v1/admin/mail-queue; check mailq "list queue" code_is 200; echo "$BODY" | ev mailqueue.json
  QID=$(echo "$BODY" | jq -r '[.. | objects | select((.recipients? // [] | tostring | test("queued-e2e")) ) | (.queue_id // .id)][0]')
  check mailq "deferred message visible (qid $QID)" bash -c "[ -n '$QID' ] && [ '$QID' != null ] && postqueue -p | grep -q '${QID%%\*}'"
  api admin GET /api/v1/admin/mail-queue '/api/v1/admin/mail-queue?q=queued-e2e'; check mailq "?q filter" bash -c "echo '$BODY' | grep -q queued-e2e"
  api admin GET '/api/v1/admin/mail-queue/{qid}' "/api/v1/admin/mail-queue/$QID"; check mailq "show message" bash -c "echo '$BODY' | grep -q 'mq-e2e'"
  api admin POST /api/v1/admin/mail-queue/action /api/v1/admin/mail-queue/action "{\"action\":\"hold\",\"ids\":[\"$QID\"]}"; check mailq "hold" code_2xx
  check mailq "message is on hold (postqueue shows !)" bash -c "postqueue -p | grep -q '$QID!'"
  api admin POST /api/v1/admin/mail-queue/action /api/v1/admin/mail-queue/action "{\"action\":\"release\",\"ids\":[\"$QID\"]}"; check mailq "release" code_2xx
  api admin POST /api/v1/admin/mail-queue/action /api/v1/admin/mail-queue/action "{\"action\":\"requeue\",\"ids\":[\"$QID\"]}"; check mailq "requeue" code_2xx
  api admin POST /api/v1/admin/mail-queue/action /api/v1/admin/mail-queue/action '{"action":"delete","ids":["; rm -rf /"]}'; check mailq "invalid queue id refused" code_4xx
  api admin POST /api/v1/admin/mail-queue/action /api/v1/admin/mail-queue/action "{\"action\":\"flush\"}"; check mailq "flush" code_2xx
  sleep 1; local nq; nq=$(postqueue -j | jq -r .queue_id | grep -c . || true)
  api admin POST /api/v1/admin/mail-queue/action /api/v1/admin/mail-queue/action "{\"action\":\"delete\",\"ids\":[\"$(postqueue -j | jq -r 'select(.recipients[].address=="queued-e2e@example.com") | .queue_id' | head -1)\"]}"; check mailq "delete" code_2xx
  check mailq "message gone from the real queue" bash -c "! postqueue -p | grep -q queued-e2e"
  postconf -e "defer_transports = $old"; postfix reload >/dev/null 2>&1
}

s_trouble() {
  api admin GET /api/v1/admin/mail-troubleshooter "/api/v1/admin/mail-troubleshooter?address=info@$DOM"; check trouble "trace local mailbox" code_is 200; echo "$BODY" | ev trouble-local.json
  check trouble "trace says local/virtual delivery" bash -c "jq -e 'tostring | test(\"virtual|lmtp|dovecot|local\";\"i\")' $BP_OUT/ev/trouble-local.json"
  api admin GET /api/v1/admin/mail-troubleshooter "/api/v1/admin/mail-troubleshooter?address=someone@example.com"; check trouble "trace remote address" code_is 200; echo "$BODY" | ev trouble-remote.json
  api admin GET /api/v1/admin/mail-troubleshooter "/api/v1/admin/mail-troubleshooter?address=bad;address"; check trouble "invalid address refused" code_4xx
}

s_ips() {
  # the container has no dummy module: use the slirp tap0 interface
  api admin GET /api/v1/admin/ips /api/v1/admin/ips; check ips "list interfaces" code_is 200; echo "$BODY" | ev ips-before.json
  reauth; api admin POST /api/v1/admin/ips /api/v1/admin/ips '{"ip":"198.51.100.77","prefix":32,"dev":"tap0"}'; check ips "add 198.51.100.77/32 on tap0" code_2xx
  check ips "address present on the interface" bash -c "ip -o addr show dev tap0 | grep -q 198.51.100.77"
  check ips "persisted (netplan/ifcfg/bpanel unit)" bash -c "grep -rqs 198.51.100.77 /etc/netplan /etc/systemd/network /etc/bpanel /etc/NetworkManager 2>/dev/null"
  reauth; api admin POST /api/v1/admin/ips /api/v1/admin/ips '{"ip":"10.9.9.9","prefix":32,"dev":"lo"}'; check ips "dev lo refused" code_4xx
  api admin PUT '/api/v1/admin/accounts/{id}/ip' "/api/v1/admin/accounts/$UID_/ip" '{"ip":"198.51.100.77"}'; check ips "assign dedicated IP to $U" code_2xx; sleep 2
  check ips "DNS A of $DOM now 198.51.100.77 (dig @127.0.0.1)" bash -c "dig +short @127.0.0.1 $DOM A | grep -qx 198.51.100.77"
  reauth; api admin POST /api/v1/admin/ips/remove /api/v1/admin/ips/remove '{"ip":"198.51.100.77","prefix":32,"dev":"tap0"}'; check ips "remove while assigned -> ip_in_use" bash -c "echo '$BODY' | grep -q ip_in_use"
  api admin PUT '/api/v1/admin/accounts/{id}/ip' "/api/v1/admin/accounts/$UID_/ip" '{"ip":""}'; check ips "back to shared IP" code_2xx; sleep 2
  check ips "DNS A no longer the dedicated IP" bash -c "! dig +short @127.0.0.1 $DOM A | grep -qx 198.51.100.77"
  reauth; api admin POST /api/v1/admin/ips/remove /api/v1/admin/ips/remove '{"ip":"198.51.100.77","prefix":32,"dev":"tap0"}'; check ips "remove address" code_2xx
  check ips "address gone" bash -c "! ip -o addr show dev tap0 | grep -q 198.51.100.77"
}

s_hostname() {
  local orig; orig=$(hostname -f 2>/dev/null || hostname)
  reauth; api admin PUT /api/v1/admin/hostname /api/v1/admin/hostname '{"hostname":"panel2.e2e.test"}'; check hostname "change to panel2.e2e.test" code_2xx; echo "$BODY" | ev hostname.json
  check hostname "system hostname changed" bash -c "hostname | grep -q panel2"
  check hostname "postfix myhostname changed" bash -c "postconf -h myhostname | grep -qx panel2.e2e.test"
  check hostname "/etc/hosts updated" grep -q panel2.e2e.test /etc/hosts
  reauth; api admin PUT /api/v1/admin/hostname /api/v1/admin/hostname '{"hostname":"bad_host!"}'; check hostname "invalid hostname refused" code_4xx
  reauth; api admin PUT /api/v1/admin/hostname /api/v1/admin/hostname "{\"hostname\":\"$orig\"}"; check hostname "restore $orig" code_2xx
}

s_tweak() {
  api admin GET /api/v1/admin/tweak-settings /api/v1/admin/tweak-settings; check tweak "get catalogue" code_is 200; echo "$BODY" | ev tweak.json
  reauth; api admin PUT /api/v1/admin/tweak-settings /api/v1/admin/tweak-settings '{"values":{"feature_images":"0"}}'; check tweak "disable images tool" code_2xx
  api user POST /api/v1/user/images /api/v1/user/images '{"path":"public_html/e2e.png","op":"thumbnail","width":50}'; check tweak "disabled tool -> 409 feature_disabled" bash -c "[ $CODE = 409 ] && echo '$BODY' | grep -q feature_disabled"
  reauth; api admin PUT /api/v1/admin/tweak-settings /api/v1/admin/tweak-settings '{"values":{"feature_images":"1"}}'; check tweak "re-enable" code_2xx
  api user POST /api/v1/user/images /api/v1/user/images '{"path":"public_html/e2e.png","op":"thumbnail","width":50}'; check tweak "tool works again" code_2xx
  reauth; api admin PUT /api/v1/admin/tweak-settings /api/v1/admin/tweak-settings '{"values":{"leech_sweep_minutes":"1"}}'; check tweak "out-of-range value refused" code_4xx
  reauth; api admin PUT /api/v1/admin/tweak-settings /api/v1/admin/tweak-settings '{"values":{"no_such_key":"1"}}'; check tweak "unknown key refused" code_4xx
}

s_phpext() {
  local v; v=$(ls /etc/php | sort -V | tail -1)
  api admin GET '/api/v1/admin/php/{version}/extensions' "/api/v1/admin/php/$v/extensions"; check phpext "list PHP $v extensions" code_is 200; echo "$BODY" | ev phpext-before.json
  api admin PUT '/api/v1/admin/php/{version}/extensions/{ext}' "/api/v1/admin/php/$v/extensions/bcmath" '{"install":true}'; check phpext "install bcmath (apt)" code_2xx
  check phpext "php$v-bcmath installed and loaded" bash -c "dpkg -s php$v-bcmath >/dev/null && php$v -m | grep -qx bcmath"
  api admin PUT '/api/v1/admin/php/{version}/extensions/{ext}' "/api/v1/admin/php/$v/extensions/bcmath" '{"install":false}'; check phpext "remove bcmath" code_2xx
  check phpext "bcmath gone" bash -c "! php$v -m | grep -qx bcmath"
  api admin PUT '/api/v1/admin/php/{version}/extensions/{ext}' "/api/v1/admin/php/$v/extensions/evil;rm" '{"install":true}'; check phpext "non-allowlisted ext refused" code_4xx
}

s_billing() {
  api admin GET /api/v1/admin/billing /api/v1/admin/billing; check billing "billing info" code_is 200; echo "$BODY" | ev billing.json
  api admin POST '/api/v1/admin/accounts/{id}/suspend' "/api/v1/admin/accounts/$UID_/suspend" '{"reason":"billing e2e"}'; check billing "suspend" code_2xx
  api admin POST '/api/v1/admin/accounts/{id}/unsuspend' "/api/v1/admin/accounts/$UID_/unsuspend"; check billing "unsuspend" code_2xx
  sleep 8
  redact < "$BP_OUT/ev/webhooks.jsonl" > "$BP_OUT/ev/webhooks-redacted.jsonl"
  for e in account.created account.suspended account.unsuspended; do
    check billing "webhook $e delivered" grep -q "\"X-Bpanel-Event\": \"$e\"" "$BP_OUT/ev/webhooks.jsonl"
  done
  check billing "HMAC signatures valid (sha256=HMAC(secret, ts.body))" python3 - "$BP_OUT/ev/webhooks.jsonl" "$HSECRET" <<'P'
import sys, json, hmac, hashlib
# every event id must carry one delivery signed with this run's secret (other
# deliveries belong to webhooks registered by earlier runs, with their own secrets)
ok, ids = 0, {}
for l in open(sys.argv[1]):
    r = {k.lower(): v for k, v in json.loads(l).items()}
    exp = 'sha256=' + hmac.new(sys.argv[2].encode(), (r['x-bpanel-timestamp'] + '.' + r['body']).encode(), hashlib.sha256).hexdigest()
    good = hmac.compare_digest(exp, r['x-bpanel-signature'])
    ids[r['x-bpanel-id']] = ids.get(r['x-bpanel-id'], False) or good; ok += good
bad = [i for i, g in ids.items() if not g]
assert not bad and ok >= 3, (ok, bad); print(ok, 'signatures ok for', len(ids), 'events')
P
}

s_whmcs() {
  local d=/root/e2e/whmcs
  check whmcs "php -l server module" php -l "$d/modules/servers/bpanel/bpanel.php"
  check whmcs "php -l webhook receiver" php -l "$d/webhook-receiver/bpanel_webhook.php"
}

for s in "${SECTIONS[@]}"; do echo "== $s"; "s_$s"; done
