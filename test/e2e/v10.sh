#!/bin/bash
# BPANEL E2E for the rows that v1.0.0 listed as "working-unverified-on-real-host" / "partial"
# (v0.4 modules). Runs INSIDE a disposable server/container as root, after v11.sh setup.
#   BP_ADMIN_PASS=… ./v10.sh [section ...]
cd "$(dirname "$0")"
source ./lib.sh
STATE="$BP_OUT/state.env"; touch "$STATE"; source "$STATE"
save() { for v in "$@"; do sed -i "/^$v=/d" "$STATE"; printf '%s=%q\n' "$v" "${!v}" >> "$STATE"; done; }
: "${W:=w${BP_TAG}}"; : "${WDOM:=${W}.${BP_TLD}}"; : "${WPASS:=WebPass${RANDOM}k5}"; : "${WMPASS:=MailPass${RANDOM}m3}"; save W WDOM WPASS WMPASS
ev() { cat > "$BP_OUT/ev/$1"; }
WH=/home/$W; WP=$WH/public_html
reauth() { api admin POST /api/v1/account/reauth /api/v1/account/reauth "$(jq -nc --arg p "$BP_ADMIN_PASS" '{password:$p}')"; }
ureauth() { api user2 POST /api/v1/account/reauth /api/v1/account/reauth "$(jq -nc --arg p "$WPASS" '{password:$p}')"; }
maildir_has() { grep -rlqs -- "$1" "$WH/mail/$WDOM/$2"; }
SECTIONS=(setup mail lists track webx git dbx dnsx ddns bandwidth tokens waf shield phpini apps installer trackdns contact usage terminal admin_modify resellers updates monitoring alerts brute firewall limits dbsettings cluster xfer plugins integrations events secrets)
[ $# -gt 0 ] && SECTIONS=("$@")

s_setup() {
  ROLE_OF_SESSION=admin login admin admin "$BP_ADMIN_USER" "$BP_ADMIN_PASS"; check setup "admin login" code_is 200
  api admin GET /api/v1/admin/packages /api/v1/admin/packages; PKG=$(jqb '[.. | objects | select(.disk_mb? != null)][0].id'); save PKG
  api admin POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"$W\",\"domain\":\"$WDOM\",\"email\":\"owner@$BP_TLD\",\"password\":\"$WPASS\",\"package_id\":$PKG,\"role\":\"user\"}"
  check setup "create account $W" code_is 200; WID=$(jqb '.account.id'); save WID
  ROLE_OF_SESSION=user login user2 user "$W" "$WPASS"; check setup "user login" code_is 200
  api user2 GET /api/v1/user/domains /api/v1/user/domains; WDID=$(echo "$BODY" | jq -r --arg n "$WDOM" '[.. | objects | select(.name? == $n)][0].id'); save WDID
  api user2 POST /api/v1/user/email/accounts /api/v1/user/email/accounts "{\"domain\":\"$WDOM\",\"local\":\"box\",\"password\":\"$WMPASS\",\"quota_mb\":50}"; check setup "mailbox box@$WDOM" code_2xx
  api user2 GET /api/v1/user/email/accounts /api/v1/user/email/accounts; WMB=$(echo "$BODY" | jq -r --arg e "box@$WDOM" '[.. | objects | select(.email? == $e)][0].id'); save WMB
}

s_mail() {
  api user2 PUT '/api/v1/user/email/autoresponders/{id}' "/api/v1/user/email/autoresponders/$WMB" '{"enabled":true,"from":"","subject":"Away (e2e)","body":"I am away until Monday.","interval_days":1}'
  check mail "autoresponder set (Sieve vacation)" code_2xx
  check mail "sieve active link + compiled" bash -c "readlink $WH/mail/$WDOM/box/dovecot.sieve && grep -q vacation $WH/mail/$WDOM/box/sieve/bpanel.sieve"
  swaks -s 127.0.0.1 -t "box@$WDOM" -f "info@$DOM" --h-Subject vac-e2e >/dev/null 2>&1; sleep 5
  check mail "vacation reply delivered to the sender's mailbox (info@$DOM)" bash -c "grep -rlqs 'Away (e2e)' /home/$U/mail/$DOM/info"
  api user2 DELETE '/api/v1/user/email/autoresponders/{id}' "/api/v1/user/email/autoresponders/$WMB"; check mail "autoresponder removed" code_2xx
  api user2 POST /api/v1/user/email/filters /api/v1/user/email/filters "{\"mailbox_id\":$WMB,\"name\":\"invoices\",\"field\":\"subject\",\"op\":\"contains\",\"value\":\"INVOICE\",\"action\":\"move\",\"target\":\"Invoices\"}"
  check mail "filter: subject contains INVOICE -> Invoices" code_2xx; FID=$(jqb '.id // .filter.id // empty')
  swaks -s 127.0.0.1 -t "box@$WDOM" -f probe@example.org --h-Subject "INVOICE 42 e2e" >/dev/null 2>&1; sleep 4
  check mail "filtered mail stored in the Invoices folder" bash -c "grep -rls 'INVOICE 42 e2e' $WH/mail/$WDOM/box/.Invoices"
  api user2 GET /api/v1/user/email/filters /api/v1/user/email/filters; FID=${FID:-$(jqb '[.. | objects | select(.name? == "invoices")][0].id')}
  api user2 POST /api/v1/user/email/filters /api/v1/user/email/filters "{\"mailbox_id\":$WMB,\"name\":\"x\",\"field\":\"subject\",\"op\":\"contains\",\"value\":\"a\",\"action\":\"move\",\"target\":\"../etc\"}"; check mail "filter folder traversal refused" code_4xx
  api user2 DELETE '/api/v1/user/email/filters/{id}' "/api/v1/user/email/filters/$FID"; check mail "filter deleted" code_2xx
  api user2 GET /api/v1/user/email/spam /api/v1/user/email/spam; check mail "spam settings" code_is 200
  api user2 PUT /api/v1/user/email/spam /api/v1/user/email/spam '{"enabled":true,"required_score":4.5,"allow":["friend@example.org"],"deny":["*@spammer.example"]}'; check mail "spam settings set (Rspamd)" code_2xx
  check mail "rspamd settings file written + rspamadm configtest" bash -c "grep -rqs 'spammer.example' /etc/rspamd/ && rspamadm configtest >/dev/null"
  # rspamd reloads asynchronously after the settings change; wait until its workers answer again
  sleep 3; for i in $(seq 1 20); do rspamc stat >/dev/null 2>&1 && break; sleep 1; done; sleep 2
  echo "Subject: denied e2e" | swaks -s 127.0.0.1 -t "box@$WDOM" -f bad@spammer.example --h-Subject spam-deny-e2e >/dev/null 2>&1; sleep 4
  check mail "deny-listed sender rejected/not in INBOX" bash -c "! grep -rqs spam-deny-e2e $WH/mail/$WDOM/box/new $WH/mail/$WDOM/box/cur"
}

s_lists() {
  api user2 POST /api/v1/user/lists /api/v1/user/lists "{\"domain\":\"$WDOM\",\"name\":\"news\",\"owner\":\"box@$WDOM\"}"; check lists "create mlmmj list news@$WDOM" code_2xx
  api user2 GET /api/v1/user/lists /api/v1/user/lists; LID=$(echo "$BODY" | jq -r '[.. | objects | select(.name? == "news")][0].id')
  api user2 POST '/api/v1/user/lists/{id}/subscribers' "/api/v1/user/lists/$LID/subscribers" "{\"address\":\"info@$DOM\"}"; check lists "subscribe info@$DOM" code_2xx
  check lists "mlmmj subscriber file" bash -c "grep -rqs 'info@$DOM' /var/spool/mlmmj/"
  swaks -s 127.0.0.1 -t "news@$WDOM" -f "box@$WDOM" --h-Subject list-post-e2e >/dev/null 2>&1; sleep 8
  check lists "post to the list reaches the subscriber's mailbox" bash -c "grep -rlqs list-post-e2e /home/$U/mail/$DOM/info"
  api user2 DELETE '/api/v1/user/lists/{id}/subscribers' "/api/v1/user/lists/$LID/subscribers?address=info@$DOM"; check lists "unsubscribe" code_2xx
  api user2 DELETE '/api/v1/user/lists/{id}' "/api/v1/user/lists/$LID"; check lists "delete list" code_2xx
}

s_track() {
  api user2 GET /api/v1/user/email/track "/api/v1/user/email/track?q=box@$WDOM&limit=50"; check track "track delivery" code_is 200; echo "$BODY" | ev track.json
  check track "postfix log entries for box@$WDOM found" bash -c "jq -e 'tostring | test(\"box@$WDOM\")' $BP_OUT/ev/track.json"
  check track "every entry involves the account's own domain" bash -c "jq -e --arg d '$WDOM' '[.entries[] | select(((.from // \"\") + \" \" + (.to // \"\")) | contains(\$d) | not)] | length == 0' $BP_OUT/ev/track.json"
}

s_webx() {
  mkdir -p $WP/img; python3 -c "open('$WP/img/p.png','wb').write(b'\x89PNG\r\n\x1a\n'+b'0'*64)"; chown -R $W:$W $WP/img
  api user2 PUT '/api/v1/user/web/{id}/hotlink' "/api/v1/user/web/$WDID/hotlink" "{\"enabled\":true,\"allowed\":[\"$WDOM\"],\"exts\":[\"png\"],\"allow_empty\":true}"; check webx "hotlink protection on" code_2xx; sleep 2
  c() { curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H "Host: $WDOM" "$@"; }
  check webx "foreign referer blocked (403)" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' -e http://evil.example/ http://127.0.0.1/img/p.png) = 403 ]"
  check webx "own referer allowed (200)" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' -e http://$WDOM/ http://127.0.0.1/img/p.png) = 200 ]"
  api user2 PUT '/api/v1/user/web/{id}/ip-blocker' "/api/v1/user/web/$WDID/ip-blocker" '{"deny":["127.0.0.7"]}'; check webx "IP blocker deny 127.0.0.7" code_2xx; sleep 2
  check webx "blocked IP gets 403, others 200" bash -c "[ \$(curl -s --noproxy '*' --interface 127.0.0.7 -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' http://127.0.0.7/) = 403 ] && [ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' http://127.0.0.1/) = 200 ]"
  api user2 PUT '/api/v1/user/web/{id}/ip-blocker' "/api/v1/user/web/$WDID/ip-blocker" '{"deny":["not-an-ip"]}'; check webx "invalid CIDR refused" code_4xx
  api user2 PUT '/api/v1/user/web/{id}/error-pages' "/api/v1/user/web/$WDID/error-pages" '{"pages":{"404":"<h1>E2E custom 404</h1>"}}'; check webx "custom 404 page" code_2xx; sleep 2
  check webx "custom 404 served" bash -c "curl -s --noproxy '*' -H 'Host: $WDOM' http://127.0.0.1/nope-e2e | grep -q 'E2E custom 404'"
  echo data > $WP/x.bpe2e; chown $W:$W $WP/x.bpe2e
  api user2 PUT '/api/v1/user/web/{id}/mime' "/api/v1/user/web/$WDID/mime" '{"types":[{"ext":"bpe2e","type":"application/x-bpanel-e2e"}]}'; check webx "MIME type .bpe2e" code_2xx; sleep 2
  check webx "served with the custom MIME type" bash -c "curl -sI --noproxy '*' -H 'Host: $WDOM' http://127.0.0.1/x.bpe2e | grep -qi 'content-type: application/x-bpanel-e2e'"
  api user2 PUT '/api/v1/user/web/{id}/privacy' "/api/v1/user/web/$WDID/privacy" '{"dirs":[{"path":"img","realm":"Private","users":[{"name":"bob","password":"BobPass1234x"}]}]}'; check webx "directory privacy /img" code_2xx; sleep 2
  check webx "privacy: 401 without, 200 with credentials" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' -e http://$WDOM/ http://127.0.0.1/img/p.png) = 401 ] && [ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -u bob:BobPass1234x -H 'Host: $WDOM' -e http://$WDOM/ http://127.0.0.1/img/p.png) = 200 ]"
  api user2 GET '/api/v1/user/web/{id}/extras' "/api/v1/user/web/$WDID/extras"; check webx "password hashes never returned" bash -c "! echo '$BODY' | grep -q '\\\$2'"
}

s_git() {
  api user2 POST /api/v1/user/git /api/v1/user/git '{"name":"site","path":"repos/site","deploy_path":"public_html/deployed"}'; check git "create empty repository" code_2xx; echo "$BODY" | ev git-create.json
  api user2 GET /api/v1/user/git /api/v1/user/git; GID=$(echo "$BODY" | jq -r '[.. | objects | select(.name? == "site")][0].id')
  local rp; rp=$(echo "$BODY" | jq -r '[.. | objects | select(.name? == "site")][0].path // "repos/site"'); [[ "$rp" = /* ]] || rp="$WH/$rp"
  runuser -u "$W" -- mkdir -p "$WP/deployed"
  runuser -u "$W" -- bash -c "set -e; d=\$(mktemp -d); cd \$d; git init -q -b main; git config user.email e2e@$WDOM; git config user.name e2e; echo '<h1>deployed by git e2e</h1>' > index.html; git add .; git commit -qm init; git push -q $rp HEAD:main 2>&1 || git push -q $rp HEAD:master" >"$BP_OUT/ev/git-push.txt" 2>&1
  check git "push into the repository as the account" bash -c "runuser -u $W -- git -C $rp log --oneline --all | grep -q init"
  api user2 POST '/api/v1/user/git/{id}/deploy' "/api/v1/user/git/$GID/deploy" '{"pull":false,"deploy":true}'; check git "deploy HEAD into public_html/deployed" code_2xx; echo "$BODY" | ev git-deploy.json
  check git "deployed page served" bash -c "curl -s --noproxy '*' -H 'Host: $WDOM' http://127.0.0.1/deployed/ | grep -q 'deployed by git e2e'"
  api user2 POST /api/v1/user/git /api/v1/user/git '{"name":"evil","clone_url":"http://127.0.0.1/x.git","path":"repos/evil"}'; check git "clone from loopback refused" code_4xx
  api user2 POST /api/v1/user/git /api/v1/user/git '{"name":"ext","clone_url":"https://github.com/cumabozkurt/bpanel.git","path":"repos/ext","branch":"main"}'; check git "clone a public https repository (network)" code_2xx
}

s_dbx() {
  api user2 POST /api/v1/user/databases /api/v1/user/databases '{"name":"app"}'; check dbx "MariaDB database ${W}_app" code_2xx
  DBPW="DbPass1${RANDOM}x1"
  api user2 POST /api/v1/user/db-users /api/v1/user/db-users "{\"name\":\"app\",\"password\":\"$DBPW\"}"; check dbx "MariaDB user ${W}_app" code_2xx
  api user2 GET /api/v1/user/databases /api/v1/user/databases; local dbid uid
  api user2 GET /api/v1/user/databases /api/v1/user/databases
  dbid=$(echo "$BODY" | jq -r --arg n "${W}_app" '.databases[] | select(.name == $n) | .id'); uid=$(echo "$BODY" | jq -r --arg n "${W}_app" '.users[] | select(.name == $n) | .id')
  api user2 POST /api/v1/user/db-grants /api/v1/user/db-grants "{\"db_id\":$dbid,\"user_id\":$uid,\"all\":true}"; check dbx "grant ALL" code_2xx
  check dbx "grant visible in MariaDB" bash -c "mysql -N -e \"SHOW GRANTS FOR '${W}_app'@'localhost'\" | grep -q 'ALL PRIVILEGES ON .${W}.*app'"
  reauth; api admin PUT /api/v1/admin/dbx/settings /api/v1/admin/dbx/settings '{"remote_enabled":true}'; check dbx "admin enables remote MySQL" code_2xx
  api user2 POST /api/v1/user/databases/remote /api/v1/user/databases/remote '{"host":"192.0.2.0/24","note":"office"}'; check dbx "remote MySQL host 192.0.2.0/24" code_2xx; echo "$BODY" | ev remote-mysql.json
  check dbx "MariaDB account ${W}_app@192.0.2.% created" bash -c "mysql -N -e \"SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='${W}_app'\" | tee /dev/stderr | grep -q '192.0.2'"
  api user2 POST /api/v1/user/databases/remote /api/v1/user/databases/remote '{"host":"%"}'; check dbx "wildcard % refused" code_4xx
  api user2 GET /api/v1/user/databases/remote /api/v1/user/databases/remote; local rid; rid=$(echo "$BODY" | jq -r '[.. | objects | select(.host? == "192.0.2.0/24")][0].id')
  ( mysql -u "${W}_app" -p"$DBPW" "${W}_app" -e 'SELECT SLEEP(25)' >/dev/null 2>&1 & ); sleep 2
  api user2 GET /api/v1/user/databases/processes /api/v1/user/databases/processes; check dbx "process list shows own SLEEP query" bash -c "echo '$BODY' | grep -qi sleep"; echo "$BODY" | ev db-processes.json
  local pid; pid=$(echo "$BODY" | jq -r '[.. | objects | select((.info? // .query? // "") | test("SLEEP";"i"))][0].id')
  api user2 POST /api/v1/user/databases/processes/kill /api/v1/user/databases/processes/kill "{\"engine\":\"mariadb\",\"id\":$pid}"; check dbx "kill own query" code_2xx
  check dbx "query gone from processlist" bash -c "sleep 1; ! mysql -N -e 'SHOW PROCESSLIST' | grep -q 'SLEEP(25)'"
  api user2 POST /api/v1/user/databases/processes/kill /api/v1/user/databases/processes/kill '{"engine":"mariadb","id":1}'; check dbx "killing a foreign/system thread refused" code_4xx
  api user2 DELETE '/api/v1/user/databases/remote/{id}' "/api/v1/user/databases/remote/$rid"; check dbx "remove remote host" code_2xx
  check dbx "remote MariaDB account dropped" bash -c "! mysql -N -e \"SELECT host FROM mysql.user WHERE user='${W}_app'\" | grep -q '192.0.2'"
}

s_dnsx() {
  api user2 GET '/api/v1/user/dnsx/{domain}/check' "/api/v1/user/dnsx/$WDOM/check"; check dnsx "zone consistency check" code_is 200
  api user2 POST '/api/v1/user/dnsx/{domain}/dnssec' "/api/v1/user/dnsx/$WDOM/dnssec" '{"enabled":true}'; check dnsx "enable DNSSEC (pdnsutil secure-zone)" code_2xx
  api user2 GET '/api/v1/user/dnsx/{domain}/dnssec' "/api/v1/user/dnsx/$WDOM/dnssec"; check dnsx "DS records returned" bash -c "echo '$BODY' | grep -q 'IN DS\\|\"ds\"'"; echo "$BODY" | ev dnssec.json
  check dnsx "RRSIG served by PowerDNS (dig +dnssec)" bash -c "dig +dnssec +short @127.0.0.1 $WDOM SOA | grep -q RRSIG || dig +dnssec @127.0.0.1 $WDOM SOA | grep -q RRSIG"
  api user2 GET '/api/v1/user/dnsx/{domain}/export' "/api/v1/user/dnsx/$WDOM/export"; check dnsx "export BIND zone" bash -c "echo '$BODY' | grep -q SOA"
  local z; z="\$ORIGIN $WDOM.
e2etxt 300 IN TXT \"imported-by-e2e\"
"
  api user2 POST '/api/v1/user/dnsx/{domain}/import/preview' "/api/v1/user/dnsx/$WDOM/import/preview" "$(jq -nc --arg t "$z" '{mode:"merge",text:$t}')"; check dnsx "import preview" code_2xx
  api user2 POST '/api/v1/user/dnsx/{domain}/import/apply' "/api/v1/user/dnsx/$WDOM/import/apply" "$(jq -nc --arg t "$z" '{mode:"merge",text:$t}')"; check dnsx "import apply (merge)" code_2xx
  check dnsx "imported TXT answered by PowerDNS" bash -c "dig +short @127.0.0.1 e2etxt.$WDOM TXT | grep -q imported-by-e2e"
  api user2 GET '/api/v1/user/dnsx/{domain}/history' "/api/v1/user/dnsx/$WDOM/history"; check dnsx "history recorded" code_is 200; local hid; hid=$(echo "$BODY" | jq -r '[.. | objects | select(.id? != null and ((tostring)|test("e2etxt")))][0].id')
  api user2 POST '/api/v1/user/dnsx/{domain}/history/{id}/revert' "/api/v1/user/dnsx/$WDOM/history/$hid/revert" '{"force":true}'; check dnsx "revert the import" code_2xx
  check dnsx "TXT gone after revert" bash -c "sleep 1; [ -z \"\$(dig +short @127.0.0.1 e2etxt.$WDOM TXT)\" ]"
  api user2 POST '/api/v1/user/dnsx/{domain}/dnssec' "/api/v1/user/dnsx/$WDOM/dnssec" '{"enabled":false}'; check dnsx "disable DNSSEC" code_2xx
}

s_ddns() {
  api user2 POST /api/v1/user/domains /api/v1/user/domains "{\"kind\":\"sub\",\"name\":\"home\",\"parent_id\":$WDID,\"docroot\":\"home\"}"; check ddns "subdomain home.$WDOM" code_2xx
  api user2 GET /api/v1/user/domains /api/v1/user/domains; local sid; sid=$(echo "$BODY" | jq -r --arg n "home.$WDOM" '[.. | objects | select(.name? == $n)][0].id')
  api user2 POST /api/v1/user/ddns /api/v1/user/ddns "{\"domain_id\":$sid}"; check ddns "enable DDNS (token shown once)" code_2xx; local tok; tok=$(jqb .token)
  local out; out=$(curl -sk --noproxy '*' --interface 127.0.0.9 "https://127.0.0.9:$BP_USER_PORT/ddns/update?token=$tok"); echo "$out" > "$BP_OUT/ev/ddns-loopback.txt"
  check ddns "loopback client address refused (badip)" grep -qx badip "$BP_OUT/ev/ddns-loopback.txt"
  out=$(curl -sk --noproxy '*' "https://127.0.0.1:$BP_USER_PORT/ddns/update?token=$tok&myip=203.0.113.9"); echo "$out" > "$BP_OUT/ev/ddns-update.txt"
  check ddns "update endpoint answers good/nochg" grep -Eq '^(good|nochg) 203.0.113.9' "$BP_OUT/ev/ddns-update.txt"
  check ddns "A record follows the reported IP" bash -c "sleep 1; dig +short @127.0.0.1 home.$WDOM A | grep -qx 203.0.113.9"
  check ddns "bad token -> badauth" bash -c "curl -sk --noproxy '*' 'https://127.0.0.1:$BP_USER_PORT/ddns/update?token=xxxxxxxx' | grep -q badauth"
}

s_bandwidth() {
  for i in $(seq 1 20); do curl -s --noproxy '*' -o /dev/null -H "Host: $WDOM" http://127.0.0.1/; done
  api admin POST /api/v1/admin/bandwidth/collect /api/v1/admin/bandwidth/collect; check bw "collect domain logs now" code_2xx
  api user2 GET /api/v1/user/bandwidth /api/v1/user/bandwidth; check bw "user bandwidth > 0 bytes for $WDOM" bash -c "echo '$BODY' | jq -e '[.. | objects | select(.domain? == \"$WDOM\") | (.bytes // .total_bytes // .out_bytes // 0)] | add > 0'"; echo "$BODY" | ev bandwidth-user.json
  api admin GET /api/v1/admin/bandwidth /api/v1/admin/bandwidth; check bw "admin bandwidth lists $W" bash -c "echo '$BODY' | grep -q '$W'"
}

s_tokens() {
  ureauth
  api user2 POST /api/v1/account/tokens /api/v1/account/tokens '{"name":"e2e-ro","perms":["hosting.read"]}'; check tokens "create API token (hosting.read)" code_2xx; local t; t=$(jqb '.token'); local tid; tid=$(jqb '.id // .token_id')
  check tokens "token reads domains" bash -c "curl -sk --noproxy '*' -H 'Authorization: Bearer $t' $USER_URL/api/v1/user/domains | grep -q '$WDOM'"
  check tokens "token cannot write (403)" bash -c "[ \$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer $t' -H 'Content-Type: application/json' --data '{\"kind\":\"sub\",\"name\":\"tk\",\"parent_id\":$WDID}' $USER_URL/api/v1/user/domains) = 403 ]"
  check tokens "token cannot use another permission area (403)" bash -c "[ \$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer $t' $USER_URL/api/v1/account/tokens) = 403 ]"
  api user2 DELETE '/api/v1/account/tokens/{id}' "/api/v1/account/tokens/$tid"; check tokens "revoke" code_2xx
  check tokens "revoked token -> 401" bash -c "[ \$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer $t' $USER_URL/api/v1/user/domains) = 401 ]"
}

s_waf() {
  api admin GET /api/v1/admin/waf /api/v1/admin/waf; check waf "WAF provider status" code_is 200; echo "$BODY" | ev waf-status.json
  api user2 PUT '/api/v1/user/waf/{domain}' "/api/v1/user/waf/$WDOM" '{"mode":"block","exclusions":[]}'; check waf "user sets WAF block mode" code_2xx; sleep 3
  check waf "SQLi probe blocked by ModSecurity + CRS (403)" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' \"http://127.0.0.1/?id=1%27%20OR%20%271%27=%271%27%20UNION%20SELECT%20password%20FROM%20users--\") = 403 ]"
  check waf "normal request still 200" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' http://127.0.0.1/) = 200 ]"
  check waf "audit log entry for the domain" bash -c "grep -rqs '$WDOM' /var/log/apache2/modsec_audit.log /var/log/modsec* 2>/dev/null"
  api user2 PUT '/api/v1/user/waf/{domain}' "/api/v1/user/waf/$WDOM" '{"mode":"audit"}'; check waf "audit (DetectionOnly) mode" code_2xx; sleep 3
  check waf "audit mode lets the probe through (200)" bash -c "[ \$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H 'Host: $WDOM' \"http://127.0.0.1/?id=1%27%20OR%20%271%27=%271%27%20UNION%20SELECT%20password%20FROM%20users--\") = 200 ]"
  reauth; api admin PUT '/api/v1/admin/accounts/{id}/waf/{domain}' "/api/v1/admin/accounts/$WID/waf/$WDOM" '{"mode":"block","lock":true}'; check waf "admin locks block mode" code_2xx
  api user2 PUT '/api/v1/user/waf/{domain}' "/api/v1/user/waf/$WDOM" '{"mode":"off"}'; check waf "user cannot override a locked mode" code_4xx
}

s_shield() {
  api admin GET /api/v1/admin/shield/status /api/v1/admin/shield/status; check shield "Shield engines status" code_is 200; echo "$BODY" | ev shield-status.json
  check shield "ClamAV engine detected" bash -c "jq -e 'tostring | test(\"clam\";\"i\")' $BP_OUT/ev/shield-status.json"
  # EICAR test string (industry-standard harmless AV test file, not malware)
  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > $WP/eicar.txt; chown $W:$W $WP/eicar.txt
  api admin POST /api/v1/admin/shield/scan /api/v1/admin/shield/scan "{\"account_id\":$WID,\"path\":\"public_html/eicar.txt\"}"; check shield "scan EICAR file" code_2xx; echo "$BODY" | ev shield-scan.json
  check shield "EICAR detected" bash -c "jq -e 'tostring | test(\"eicar|infected|detect\";\"i\")' $BP_OUT/ev/shield-scan.json"
  api admin GET /api/v1/admin/shield/detections /api/v1/admin/shield/detections; check shield "detection recorded" bash -c "echo '$BODY' | grep -qi eicar"
  api user2 GET /api/v1/user/shield/detections /api/v1/user/shield/detections; check shield "user sees own detection" bash -c "echo '$BODY' | grep -qi eicar"
  api admin GET /api/v1/admin/shield/quarantine /api/v1/admin/shield/quarantine; echo "$BODY" | ev shield-quarantine.json
  check shield "file quarantined (moved out of the docroot) or reported per policy" bash -c "[ ! -e $WP/eicar.txt ] || jq -e 'tostring|test(\"report|monitor\";\"i\")' $BP_OUT/ev/shield-scan.json"
  echo '<?php echo "clean"; ?>' > $WP/clean.php; chown $W:$W $WP/clean.php
  api admin POST /api/v1/admin/shield/scan /api/v1/admin/shield/scan "{\"account_id\":$WID,\"path\":\"public_html/clean.php\"}"; check shield "clean file scans clean" bash -c "[ $CODE = 200 ] && ! echo '$BODY' | grep -qi 'eicar'"
}

s_phpini() {
  local v; v=$(ls /etc/php | sort -V | tail -1)
  api user2 GET /api/v1/user/php-ini "/api/v1/user/php-ini?version=$v"; check phpini "get PHP $v settings" code_is 200
  api user2 PUT /api/v1/user/php-ini /api/v1/user/php-ini "{\"version\":\"$v\",\"settings\":{\"memory_limit\":\"192M\",\"max_execution_time\":\"45\"}}"; check phpini "set memory_limit=192M" code_2xx; sleep 3
  echo '<?php echo ini_get("memory_limit"),"|",ini_get("max_execution_time");' > $WP/ini.php; chown $W:$W $WP/ini.php
  check phpini "PHP-FPM pool applies it (live request)" bash -c "curl -s --noproxy '*' -H 'Host: $WDOM' http://127.0.0.1/ini.php | grep -q '192M|45'"
  api user2 PUT /api/v1/user/php-ini /api/v1/user/php-ini "{\"version\":\"$v\",\"settings\":{\"disable_functions\":\"\"}}"; check phpini "non-allowlisted directive refused" code_4xx
}

s_apps() {
  api admin GET /api/v1/admin/apps/settings /api/v1/admin/apps/settings; check apps "runtimes detected" bash -c "echo '$BODY' | grep -qi node"; echo "$BODY" | ev apps-settings.json
  mkdir -p $WH/nodeapp; cat > $WH/nodeapp/app.js <<'JS'
const http = require('http'); const p = process.env.PORT;
http.createServer((q, s) => { s.end('hello from node e2e on ' + p); }).listen(p, '127.0.0.1');
JS
  chown -R $W:$W $WH/nodeapp
  api user2 POST /api/v1/user/apps /api/v1/user/apps "{\"name\":\"nodee2e\",\"runtime\":\"node\",\"version\":\"$(jq -r '.runtimes[] | select(.runtime=="node") | .version' $BP_OUT/ev/apps-settings.json)\",\"root\":\"nodeapp\",\"startup\":\"app.js\",\"domain_id\":$WDID,\"url_path\":\"/node\"}"; check apps "create Node.js app" code_2xx; echo "$BODY" | ev app-create.json
  local aid; aid=$(jqb '.id // .app.id')
  api user2 POST '/api/v1/user/apps/{id}/ctl' "/api/v1/user/apps/$aid/ctl" '{"action":"start"}'; check apps "start (systemd bpanel-app@ unit)" code_2xx; sleep 4
  check apps "unit active" bash -c "systemctl list-units --all 'bpanel-app@*' --no-legend | grep -q active"
  check apps "app reachable through the domain (/node)" bash -c "curl -s --noproxy '*' -H 'Host: $WDOM' http://127.0.0.1/node/ | grep -q 'hello from node e2e'"
  api user2 GET '/api/v1/user/apps/{id}/logs' "/api/v1/user/apps/$aid/logs"; check apps "journal logs" code_is 200
  check apps "app runs as the account user" bash -c "ps -o user= -C node | grep -qx '$W'"
  api user2 POST '/api/v1/user/apps/{id}/ctl' "/api/v1/user/apps/$aid/ctl" '{"action":"stop"}'; check apps "stop" code_2xx
  api user2 DELETE '/api/v1/user/apps/{id}' "/api/v1/user/apps/$aid"; check apps "delete" code_2xx
}

s_installer() {
  api user2 GET /api/v1/user/installer/catalog /api/v1/user/installer/catalog; check inst "catalogue" code_is 200
  api admin POST /api/v1/admin/apps/wpcli /api/v1/admin/apps/wpcli; check inst "install WP-CLI (sha512 verified)" code_2xx; echo "$BODY" | ev wpcli.json
  api user2 POST /api/v1/user/installer/install /api/v1/user/installer/install "{\"app\":\"wordpress\",\"domain_id\":$WDID,\"path\":\"wp\"}"; check inst "install WordPress into /wp" code_2xx; echo "$BODY" | ev wp-install.json
  local i; for i in $(seq 1 60); do [ -f $WP/wp/wp-config.php ] && break; sleep 3; done
  check inst "wp-config.php written, files owned by $W" bash -c "stat -c %U $WP/wp/wp-config.php | grep -qx $W"
  sleep 20; check inst "Shield real-time scan flags no WordPress core file" bash -c "! jq -r 'select(.outcome==\"infected\") | .path' /var/lib/bpanel/shield/journal.jsonl | grep -q '^/home/$W/public_html/wp/'"
  check inst "WordPress answers over HTTP" bash -c "curl -sL -m 30 --noproxy '*' --resolve $WDOM:80:127.0.0.1 http://$WDOM/wp/ | grep -qi 'wordpress'"
  api user2 GET /api/v1/user/installer/installs /api/v1/user/installer/installs; local iid; iid=$(echo "$BODY" | jq -r '[.. | objects | select(.app? == "wordpress")][0].id'); echo "$BODY" | ev installs.json
  api user2 GET '/api/v1/user/wordpress/{id}' "/api/v1/user/wordpress/$iid"; check inst "WordPress Toolkit details" code_is 200; echo "$BODY" | ev wp-details.json
  api user2 POST '/api/v1/user/wordpress/{id}/maintenance' "/api/v1/user/wordpress/$iid/maintenance" '{"on":true}'; check inst "maintenance on" code_2xx
  check inst ".maintenance file present" test -f $WP/wp/.maintenance
  api user2 POST '/api/v1/user/wordpress/{id}/maintenance' "/api/v1/user/wordpress/$iid/maintenance" '{"on":false}'; check inst "maintenance off" code_2xx
}

s_trackdns() {
  api user2 GET /api/v1/user/dns-lookup "/api/v1/user/dns-lookup?host=$WDOM&type=A"; check tdns "dns lookup own domain" code_is 200
  # Track DNS uses the system resolver (like cPanel). The sandbox resolver returns no NS data at
  # all (not even for public zones), so this check only runs where the resolver can answer it.
  if [ -n "$(dig +short +time=3 NS "$WDOM" 2>/dev/null)" ]; then
    api user2 GET /api/v1/user/dns-lookup "/api/v1/user/dns-lookup?host=$WDOM&type=NS"; check tdns "dns lookup NS of the own zone" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -qi 'ns1\\|ns2'"
  else
    skip tdns "dns lookup NS of the own zone" "environment: the container's upstream resolver answers no NS queries"
  fi
  api user2 POST /api/v1/user/traceroute /api/v1/user/traceroute '{"host":"127.0.0.1"}'; check tdns "traceroute to loopback refused" code_4xx
  api user2 POST /api/v1/user/traceroute /api/v1/user/traceroute '{"host":"9.9.9.9"}'; check tdns "traceroute to a public IP runs" bash -c "[ $CODE = 200 ] || echo '$BODY' | grep -q not_installed"; echo "$BODY" | ev traceroute.json
}

s_contact() {
  api user2 PUT /api/v1/user/contact-email /api/v1/user/contact-email '{"email":"new-owner@example.org"}'; check contact "change contact email" code_2xx
  api user2 GET /api/v1/user/contact-email /api/v1/user/contact-email; check contact "persisted" bash -c "echo '$BODY' | grep -q new-owner@example.org"
  api user2 GET /api/v1/user/user-manager /api/v1/user/user-manager; check umgr "User Manager lists mailbox box@$WDOM" bash -c "echo '$BODY' | grep -q 'box@$WDOM'"
}

s_usage() {
  api admin GET /api/v1/admin/isolation/status /api/v1/admin/isolation/status; check usage "cgroup v2 support" code_is 200; echo "$BODY" | ev isolation-status.json
  sleep 1; api user2 GET /api/v1/user/usage '/api/v1/user/usage?range=1h'; check usage "user resource usage" code_is 200; echo "$BODY" | ev usage.json
  api admin GET /api/v1/admin/usage/top /api/v1/admin/usage/top; check usage "top consumers" code_is 200
}

s_terminal() {
  api admin PUT '/api/v1/admin/accounts/{id}/modify' "/api/v1/admin/accounts/$WID/modify" '{"shell_access":true}'; check term "enable shell access" code_2xx
  api user2 GET /api/v1/user/terminal /api/v1/user/terminal; check term "terminal status" code_is 200; echo "$BODY" | ev terminal-status.json
  ureauth; check term "WebSocket shell session runs as the account (id -un, arithmetic echo)" bash -c "set -o pipefail; python3 ./wsterm.py $BP_OUT/jars/user2.jar $USER_URL $W | tee $BP_OUT/ev/terminal-session.txt"
  sleep 1; api admin GET /api/v1/admin/audit "/api/v1/admin/audit?q=terminal.open&limit=20"; check term "session audited (terminal.open)" bash -c "echo '$BODY' | grep -q 'terminal.open'"
}

s_admin_modify() {
  api admin GET '/api/v1/admin/accounts/{id}/modify' "/api/v1/admin/accounts/$WID/modify"; check modify "get modify form" code_is 200; local ver; ver=$(jqb '.version // 0')
  api admin PUT '/api/v1/admin/accounts/{id}/modify' "/api/v1/admin/accounts/$WID/modify" "{\"email\":\"changed@$BP_TLD\",\"max_subdomains\":7,\"version\":$ver}"; check modify "change contact + subdomain override" code_2xx
  api admin GET '/api/v1/admin/accounts/{id}/modify' "/api/v1/admin/accounts/$WID/modify"; check modify "persisted" bash -c "echo '$BODY' | grep -q 'changed@$BP_TLD'"
  api admin PUT '/api/v1/admin/accounts/{id}/modify' "/api/v1/admin/accounts/$WID/modify" "{\"email\":\"x@$BP_TLD\",\"version\":1}"; check modify "stale version -> conflict" code_4xx
}

s_resellers() {
  local R="r${BP_TAG}"
  api admin POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"$R\",\"domain\":\"$R.$BP_TLD\",\"email\":\"r@$BP_TLD\",\"password\":\"$WPASS\",\"package_id\":$PKG,\"role\":\"reseller\",\"max_accounts\":1}"
  check resl "create reseller" code_is 200; local rid; rid=$(jqb '.account.id')
  ROLE_OF_SESSION=reseller login resl admin "$R" "$WPASS"; check resl "reseller login" code_is 200
  # a reseller sells its own packages: allowed_packages may only name packages it owns
  api resl POST /api/v1/admin/packages /api/v1/admin/packages '{"name":"resl-basic","disk_mb":1000,"bandwidth_mb":1000,"max_domains":1,"max_subdomains":2,"max_aliases":1,"max_email":5,"max_db":2,"max_ftp":1,"mail_quota_mb":100,"cpu_percent":50,"memory_mb":512,"max_tasks":64}'
  check resl "reseller creates own package" code_2xx; local rpkg; rpkg=$(jqb '.id // .package.id')
  api admin PUT '/api/v1/admin/resellers/{id}/limits' "/api/v1/admin/resellers/$rid/limits" "{\"max_accounts\":1,\"disk_mb\":5000,\"bandwidth_mb\":5000,\"allowed_packages\":[$rpkg],\"acl\":[\"admin.read\",\"accounts.read\",\"accounts.create\",\"packages.read\"]}"; check resl "Edit Reseller limits/ACL" code_2xx
  api resl POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"c0${BP_TAG}\",\"domain\":\"c0${BP_TAG}.$BP_TLD\",\"email\":\"c@$BP_TLD\",\"password\":\"$WPASS\",\"package_id\":$PKG,\"role\":\"user\"}"; check resl "package not in allowed_packages refused" code_4xx
  api resl POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"c1${BP_TAG}\",\"domain\":\"c1${BP_TAG}.$BP_TLD\",\"email\":\"c@$BP_TLD\",\"password\":\"$WPASS\",\"package_id\":$rpkg,\"role\":\"user\"}"; check resl "reseller creates 1st customer" code_is 200
  api resl POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"c2${BP_TAG}\",\"domain\":\"c2${BP_TAG}.$BP_TLD\",\"email\":\"c@$BP_TLD\",\"password\":\"$WPASS\",\"package_id\":$rpkg,\"role\":\"user\"}"; check resl "max_accounts=1 enforced" code_4xx
  api resl POST '/api/v1/admin/accounts/{id}/suspend' "/api/v1/admin/accounts/$WID/suspend" '{"reason":"x"}'; check resl "ACL without suspend: cannot suspend (and not own)" bash -c "[[ $CODE == 403 || $CODE == 404 ]]"
}

s_updates() {
  api admin GET /api/v1/admin/updates/status /api/v1/admin/updates/status; check upd "pending updates probe (apt)" code_is 200; echo "$BODY" | ev updates-status.json
  api admin PUT /api/v1/admin/updates/prefs /api/v1/admin/updates/prefs '{"policy":"security","auto_reboot":"never"}'; check upd "set policy=security" code_2xx
  api admin GET /api/v1/admin/updates/prefs /api/v1/admin/updates/prefs; check upd "policy=security persisted" bash -c "echo '$BODY' | jq -e '.prefs.policy == \"security\"'"
  reauth; api admin POST /api/v1/admin/updates/apply /api/v1/admin/updates/apply '{}'; check upd "security-only apply runs unattended-upgrade" bash -c "[ $CODE -lt 300 ] || echo '$BODY' | grep -q unsupported"; echo "$BODY" | ev updates-apply.json
  api admin PUT /api/v1/admin/updates/prefs /api/v1/admin/updates/prefs '{"policy":"yolo"}'; check upd "invalid policy refused" code_4xx
}

s_monitoring() {
  api admin GET /api/v1/admin/obsx/health /api/v1/admin/obsx/health; check mon "OS health (time sync, SMART, failed units…)" code_is 200; echo "$BODY" | ev obsx-health.json
  check mon "health reports real data (time sync section present)" bash -c "jq -e 'tostring|test(\"chrony|timesync|ntp\";\"i\")' $BP_OUT/ev/obsx-health.json"
  check mon "/metrics exposes Prometheus text" bash -c "curl -sk --noproxy '*' $ADMIN_URL/metrics | grep -q '^bpanel_' || curl -sk --noproxy '*' https://127.0.0.1:$BP_ADMIN_PORT/api/v1/metrics | grep -q '^bpanel_'"
  api admin POST /api/v1/admin/obsx/fim/baseline /api/v1/admin/obsx/fim/baseline; check mon "FIM baseline" code_2xx; sleep 3
  echo "# e2e tamper" >> /etc/bpanel/capabilities.json.e2e-probe 2>/dev/null; echo "# bpanel e2e fim probe" > /etc/nginx/conf.d/zz-bpanel-e2e-probe.conf
  api admin POST /api/v1/admin/obsx/fim/check /api/v1/admin/obsx/fim/check; echo "$BODY" | ev fim-check.json; check mon "FIM check detects a new file in /etc/nginx" bash -c "grep -q 'bpanel-e2e-probe' $BP_OUT/ev/fim-check.json"
  rm -f /etc/nginx/conf.d/zz-bpanel-e2e-probe.conf /etc/bpanel/capabilities.json.e2e-probe
}

s_alerts() {
  api admin POST /api/v1/admin/obsx/channels /api/v1/admin/obsx/channels "{\"name\":\"e2e-mail\",\"kind\":\"email\",\"target\":\"box@$WDOM\",\"min_severity\":\"info\",\"enabled\":true}"; check alerts "email channel" code_2xx; local cid; cid=$(jqb '.id // .channel.id')
  api admin POST '/api/v1/admin/obsx/channels/{id}/test' "/api/v1/admin/obsx/channels/$cid/test"; check alerts "test notification sent" code_2xx; sleep 6
  check alerts "test notification delivered to box@$WDOM" bash -c "grep -rlis 'bpanel\\|test' $WH/mail/$WDOM/box/new | xargs grep -lis 'notification\\|test' | grep -q ."
  api admin PUT '/api/v1/admin/obsx/rules/{rule}' "/api/v1/admin/obsx/rules/disk_full" '{"enabled":true,"threshold":1,"severity":"warning","cooldown_sec":60}'; check alerts "rule override (disk_full threshold 1%)" code_2xx
  api admin POST /api/v1/admin/obsx/evaluate /api/v1/admin/obsx/evaluate; check alerts "evaluate now" code_2xx; sleep 2
  api admin GET /api/v1/admin/obsx/incidents '/api/v1/admin/obsx/incidents?status=open'; check alerts "incident opened" bash -c "echo '$BODY' | jq -e '[.. | objects | select(.id? != null and .rule? != null)] | length > 0'"; echo "$BODY" | ev incidents.json
  local iid; iid=$(echo "$BODY" | jq -r '[.. | objects | select(.id? != null and .rule? != null)][0].id')
  api admin POST '/api/v1/admin/obsx/incidents/{id}/action' "/api/v1/admin/obsx/incidents/$iid/action" '{"action":"ack","note":"e2e"}'; check alerts "acknowledge incident" code_2xx
  api admin PUT '/api/v1/admin/obsx/rules/{rule}' "/api/v1/admin/obsx/rules/disk_full" '{"enabled":true,"threshold":90,"severity":"warning","cooldown_sec":3600}'
}

s_brute() {
  api admin GET /api/v1/admin/brute-force /api/v1/admin/brute-force; check brute "fail2ban jails listed" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -qi jail"; echo "$BODY" | ev brute.json
  ip addr add 192.0.2.66/32 dev lo 2>/dev/null; for i in $(seq 1 10); do curl -sk --noproxy '*' --interface 192.0.2.66 -o /dev/null -H 'Content-Type: application/json' -H "Origin: https://192.0.2.66:$BP_USER_PORT" --data '{"username":"nobody","password":"wrong-e2e"}' "https://192.0.2.66:$BP_USER_PORT/api/v1/auth/login"; done; sleep 6
  api admin GET /api/v1/admin/brute-force /api/v1/admin/brute-force; echo "$BODY" | ev brute-after.json
  check brute "repeated panel login failures from 192.0.2.66 banned by the bpanel jail" bash -c "grep -q 192.0.2.66 $BP_OUT/ev/brute-after.json || fail2ban-client status bpanel | grep -q 192.0.2.66"
  check brute "ban enforced in nftables" bash -c "nft list ruleset | grep -q 192.0.2.66"
  fail2ban-client set bpanel unbanip 192.0.2.66 >/dev/null 2>&1; ip addr del 192.0.2.66/32 dev lo 2>/dev/null
  # an entry left by an earlier run is removed first, so the add is exercised again
  api admin GET /api/v1/admin/brute-force /api/v1/admin/brute-force; for i in $(echo "$BODY" | jq -r '.. | objects | select(.ip? == "198.51.100.10" and .id? != null) | .id'); do api admin DELETE '/api/v1/admin/brute-force/allowlist/{id}' "/api/v1/admin/brute-force/allowlist/$i"; done
  api admin POST /api/v1/admin/brute-force/allowlist /api/v1/admin/brute-force/allowlist '{"ip":"198.51.100.10","note":"office"}'; check brute "allowlist IP" code_2xx
  check brute "pushed to fail2ban ignoreip (runtime)" bash -c "fail2ban-client get bpanel ignoreip | grep -q 198.51.100.10"
}

s_firewall() {
  api admin GET /api/v1/admin/firewall/status /api/v1/admin/firewall/status; check fw "firewall status (nftables)" code_is 200; echo "$BODY" | ev fw-status.json
  api admin POST /api/v1/admin/firewall/rules /api/v1/admin/firewall/rules '{"action":"deny","cidr":"203.0.113.0/24","proto":"tcp","ports":[8443],"comment":"e2e","family":"ip"}'; check fw "add deny rule 203.0.113.0/24:8443" code_2xx
  reauth; api admin POST /api/v1/admin/firewall/apply /api/v1/admin/firewall/apply '{"confirm_seconds":60}'; check fw "apply with confirm window" code_2xx; echo "$BODY" | ev fw-apply.json
  local ver tok; ver=$(jqb '.version // .pending.version'); tok=$(jqb '.token // .pending.token // .confirm_token')
  check fw "rule live in nft table inet bpanel" bash -c "nft list table inet bpanel | grep -q 203.0.113.0/24"
  api admin POST /api/v1/admin/firewall/confirm /api/v1/admin/firewall/confirm "{\"version\":$ver,\"token\":\"$tok\"}"; check fw "confirm" code_2xx
  api admin POST /api/v1/admin/firewall/blocks /api/v1/admin/firewall/blocks '{"ip":"203.0.113.77","reason":"e2e","timeout_seconds":120}'; check fw "temporary block 203.0.113.77" code_2xx
  check fw "temporary block in nftables set" bash -c "sleep 1; nft list table inet bpanel | grep -q 203.0.113.77"
  api admin POST /api/v1/admin/firewall/rules /api/v1/admin/firewall/rules '{"action":"deny","cidr":"0.0.0.0/0","proto":"tcp","ports":[2087],"family":"ip"}'; check fw "lockout guard refuses dropping the admin port for everyone" code_4xx
  api admin GET /api/v1/admin/firewall/rules /api/v1/admin/firewall/rules; local rid; rid=$(echo "$BODY" | jq -r '[.. | objects | select(.comment? == "e2e")][0].id')
  api admin DELETE '/api/v1/admin/firewall/rules/{id}' "/api/v1/admin/firewall/rules/$rid"; reauth; api admin POST /api/v1/admin/firewall/apply /api/v1/admin/firewall/apply '{"confirm_seconds":30}'
  sleep 40; check fw "unconfirmed apply rolled back automatically (rule restored)" bash -c "nft list table inet bpanel | grep -q 203.0.113.0/24"
  api admin GET /api/v1/admin/firewall/history /api/v1/admin/firewall/history; echo "$BODY" | ev fw-history.json
  reauth; api admin POST /api/v1/admin/firewall/apply /api/v1/admin/firewall/apply '{"confirm_seconds":60}'; ver=$(jqb '.version // .pending.version'); tok=$(jqb '.token // .pending.token // .confirm_token')
  api admin POST /api/v1/admin/firewall/confirm /api/v1/admin/firewall/confirm "{\"version\":$ver,\"token\":\"$tok\"}"; check fw "rule removed after confirmed apply" bash -c "! nft list table inet bpanel | grep -q 203.0.113.0/24"
}

s_limits() {
  api admin POST /api/v1/admin/limit-profiles /api/v1/admin/limit-profiles '{"name":"e2e-small-'"$BP_TAG"'","cpu_percent":50,"mem_max_mb":256,"mem_high_mb":200,"tasks_max":64}'; check limits "create limit profile" code_2xx; local pid; pid=$(jqb '.id // .profile.id')
  api admin PUT '/api/v1/admin/accounts/{id}/limits' "/api/v1/admin/accounts/$WID/limits" "{\"profile_id\":$pid}"; check limits "assign to $W" code_2xx; echo "$BODY" | ev limits-apply.json; sleep 2
  check limits "systemd slice carries CPUQuota/MemoryMax/TasksMax" bash -c "s=\$(systemctl list-units --all --no-legend '*$W*.slice' | awk '{print \$1}' | head -1); [ -n \"\$s\" ] && systemctl show \$s -p CPUQuotaPerSecUSec -p MemoryMax -p TasksMax | tee /dev/stderr | grep -q 'TasksMax=64'"
  local sl; sl=$(systemctl list-units --all --no-legend --plain '*'"$W"'*.slice' | awk '{print $1}' | head -1)
  systemd-run --quiet --uid="$W" --slice="$sl" --unit="bpanel-e2e-lim-$W" sleep 20 >/dev/null 2>&1; sleep 1
  check limits "cgroup files enforce it (memory.max, pids.max)" bash -c "f=\$(find /sys/fs/cgroup -type d -name '$sl' | head -1); [ -n \"\$f\" ] && grep -qx 268435456 \$f/memory.max && grep -qx 64 \$f/pids.max"
  systemctl stop "bpanel-e2e-lim-$W" 2>/dev/null
  api admin POST /api/v1/admin/limit-profiles /api/v1/admin/limit-profiles '{"name":"bad","mem_max_mb":100,"mem_high_mb":200}'; check limits "mem_high > mem_max refused" code_4xx
}

s_dbsettings() {
  api admin GET /api/v1/admin/dbx/settings /api/v1/admin/dbx/settings; check dbset "DB engine settings (PostgreSQL ok)" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -q '\"ok\"'"; echo "$BODY" | ev dbx-settings.json
  api admin PUT '/api/v1/admin/accounts/{id}/db-limits' "/api/v1/admin/accounts/$WID/db-limits" '{"max_user_connections":7}'; check dbset "MAX_USER_CONNECTIONS=7" code_2xx
  check dbset "MariaDB user limit applied" bash -c "mysql -N -e \"SELECT max_user_connections FROM mysql.user WHERE user='${W}_app'\" | grep -qx 7"
}

s_cluster() {
  api admin POST /api/v1/admin/dns-cluster/secondaries /api/v1/admin/dns-cluster/secondaries '{"ip":"192.0.2.53","name":"ns2.e2e.test"}'; check cluster "add secondary 192.0.2.53" code_2xx
  check cluster "PowerDNS allow-axfr-ips/also-notify updated" bash -c "grep -rqs 192.0.2.53 /etc/powerdns/"
  check cluster "AXFR refused from a non-secondary IP" bash -c "dig @127.0.0.1 $WDOM AXFR | grep -qi 'failed\\|refused\\|Transfer failed'"
  api admin GET /api/v1/admin/dns-cluster/status /api/v1/admin/dns-cluster/status; check cluster "status per zone/secondary" code_is 200; echo "$BODY" | ev cluster-status.json
  api admin GET /api/v1/admin/dns-cluster /api/v1/admin/dns-cluster; local sid; sid=$(echo "$BODY" | jq -r '[.. | objects | select(.ip? == "192.0.2.53")][0].id')
  api admin DELETE '/api/v1/admin/dns-cluster/secondaries/{id}' "/api/v1/admin/dns-cluster/secondaries/$sid"; check cluster "remove secondary" code_2xx
}

s_xfer() {
  # a previous run's import is terminated first (fixed archive user/domain)
  api admin GET /api/v1/admin/accounts /api/v1/admin/accounts; local oid; oid=$(echo "$BODY" | jq -r '[.. | objects | select(.username? == "olde2e")][0].id // empty')
  if [ -n "$oid" ]; then reauth; api admin DELETE '/api/v1/admin/accounts/{id}' "/api/v1/admin/accounts/$oid"; sleep 8; fi
  rm -f /var/lib/bpanel/xfer/cpmove-olde2e.tar.gz
  local t=/tmp/xfer-e2e; rm -rf $t; mkdir -p $t/cpmove-olde2e/{cp,userdata,homedir/public_html,mysql,dnszones,va,etc/old-e2e.test}
  cd $t/cpmove-olde2e
  printf 'DNS=old-e2e.test\nPLAN=default\nCONTACTEMAIL=old@example.org\n' > cp/olde2e
  printf -- '---\nmain_domain: old-e2e.test\naddon_domains: {}\nparked_domains: []\nsub_domains: []\n' > userdata/main
  printf -- '---\ndocumentroot: /home/olde2e/public_html\n' > userdata/old-e2e.test
  echo '<h1>migrated from cPanel e2e</h1>' > homedir/public_html/index.html
  printf 'CREATE TABLE t (id int);\nINSERT INTO t VALUES (42);\n' > mysql/olde2e_shop.sql
  printf '$TTL 300\n@ IN SOA ns1.old-e2e.test. hostmaster.old-e2e.test. 1 3600 600 86400 300\n@ IN NS ns1.old-e2e.test.\n@ IN A 192.0.2.10\nlegacy IN TXT "from-cpmove"\n' > dnszones/old-e2e.test.db
  printf 'sales@old-e2e.test: someone@example.org\n' > va/old-e2e.test
  printf 'mail:x:1000:1000::/home/olde2e/mail/old-e2e.test/mail:/bin/false\n' > etc/old-e2e.test/passwd
  printf 'mail:%s:19000::::::\n' "$(openssl passwd -6 OldMailPass123)" > etc/old-e2e.test/shadow
  printf 'mail:52428800\n' > etc/old-e2e.test/quota
  cd $t && tar czf /var/lib/bpanel/xfer/cpmove-olde2e.tar.gz cpmove-olde2e && cd - >/dev/null
  api admin GET /api/v1/admin/xfer/archives /api/v1/admin/xfer/archives; check xfer "archive listed" bash -c "echo '$BODY' | grep -q cpmove-olde2e"
  api admin POST /api/v1/admin/xfer/analyse /api/v1/admin/xfer/analyse '{"archive":"cpmove-olde2e.tar.gz"}'; check xfer "analyse cpmove (format cpanel)" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -qi cpanel"; echo "$BODY" | ev xfer-analyse.json
  reauth; api admin POST /api/v1/admin/xfer/import /api/v1/admin/xfer/import "{\"archive\":\"cpmove-olde2e.tar.gz\",\"package_id\":$PKG}"; check xfer "import as a new account (job)" code_2xx; echo "$BODY" | ev xfer-import.json
  local i; for i in $(seq 1 60); do id olde2e >/dev/null 2>&1 && [ -f /home/olde2e/public_html/index.html ] && break; sleep 3; done; sleep 5
  check xfer "imported site served" bash -c "curl -s --noproxy '*' -H 'Host: old-e2e.test' http://127.0.0.1/ | grep -q 'migrated from cPanel e2e'"
  check xfer "imported DNS record served" bash -c "dig +short @127.0.0.1 legacy.old-e2e.test TXT | grep -q from-cpmove"
  check xfer "imported database has the row" bash -c "mysql -N -e 'SELECT id FROM olde2e_shop.t' | grep -qx 42"
  check xfer "imported mailbox keeps its password (IMAP login)" bash -c "curl -s --noproxy '*' -k --url 'imaps://127.0.0.1/' --user 'mail@old-e2e.test:OldMailPass123' -X 'LIST \"\" \"*\"' | grep -qi inbox"
  api admin GET /api/v1/admin/xfer/imports /api/v1/admin/xfer/imports; echo "$BODY" | ev xfer-history.json
}

s_plugins() {
  local d=/tmp/plug; rm -rf $d; mkdir -p $d; cp -r /root/e2e/plugin/* $d/
  local pub; pub=$(cat $d/key.pub)
  api admin GET /api/v1/admin/plugins /api/v1/admin/plugins; for i in $(echo "$BODY" | jq -r '.. | objects | select(.name? == "e2e" and .key_id? != null) | .id'); do api admin DELETE '/api/v1/admin/plugin-keys/{id}' "/api/v1/admin/plugin-keys/$i"; done
  reauth; api admin POST /api/v1/admin/plugin-keys /api/v1/admin/plugin-keys "$(jq -nc --arg p "$pub" '{name:"e2e",pubkey:$p}')"; check plug "trust signing key" code_2xx
  local a; a=$(base64 -w0 $d/hello.tar.gz)
  api admin POST /api/v1/admin/plugins/inspect /api/v1/admin/plugins/inspect "{\"archive\":\"$a\"}"; check plug "inspect signed plugin" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -qi hello"
  reauth; api admin POST /api/v1/admin/plugins /api/v1/admin/plugins "{\"archive\":\"$a\"}"; check plug "install (disabled)" code_2xx
  local name; name=$(jq -r .name $d/plugin.json)
  api admin POST '/api/v1/admin/plugins/{name}/enable' "/api/v1/admin/plugins/$name/enable" '{"enabled":true}'; check plug "enable" code_2xx
  check plug "plugin UI served sandboxed (CSP sandbox)" bash -c "curl -sk -D - -o /dev/null -b $BP_OUT/jars/admin.jar $ADMIN_URL/api/v1/admin/plugins/$name/ui/index.html | grep -qi 'content-security-policy:.*sandbox'"
  local bad; bad=$(base64 -w0 $d/unsigned.tar.gz)
  reauth; api admin POST /api/v1/admin/plugins /api/v1/admin/plugins "{\"archive\":\"$bad\"}"; check plug "unsigned/untrusted archive refused" code_4xx
  api admin DELETE '/api/v1/admin/plugins/{name}' "/api/v1/admin/plugins/$name"; check plug "remove" code_2xx
}

s_integrations() {
  api admin GET /api/v1/admin/integrations /api/v1/admin/integrations; check integ "inventory" code_is 200; echo "$BODY" | ev integrations.json
  check integ "installed providers reported with versions (fail2ban, rspamd)" bash -c "jq -e '[.providers[] | select(.state==\"installed\" and (.name==\"fail2ban\" or .name==\"rspamd\"))] | length == 2' $BP_OUT/ev/integrations.json"
  api admin GET /api/v1/admin/shield/status /api/v1/admin/shield/status; echo "$BODY" | ev shield-engines.json; check integ "ClamAV + YARA engines detected by Shield" bash -c "jq -e 'tostring | test(\"clam\";\"i\") and test(\"yara\";\"i\")' $BP_OUT/ev/shield-engines.json"
}

s_events() {
  api admin GET /api/v1/admin/events '/api/v1/admin/events?limit=50'; check events "security events feed" bash -c "[ $CODE = 200 ] && echo '$BODY' | jq -e '[.. | objects | select(.type? != null)] | length > 0'"; echo "$BODY" | ev events.json
  api admin GET /api/v1/admin/audit '/api/v1/admin/audit?limit=200'; check events "audit trail has v1.1 actions" bash -c "echo '$BODY' | grep -q 'mailqueue.action\\|images.process\\|hostname'"
}

s_secrets() {
  check secrets "master key file 0600 owned by bpanel (outside /etc for ProtectSystem)" bash -c "stat -c '%a %U' /var/lib/bpanel/keys/secret.key | grep -qx '600 bpanel'"
  check secrets "no secret value in plain text in the DB (webhook secret)" bash -c "! sqlite3 /var/lib/bpanel/db/bpanel.db .dump | grep -q '$HSECRET'"
  reauth; api admin POST /api/v1/admin/secrets/rotate /api/v1/admin/secrets/rotate; check secrets "rotate master key" code_2xx
  api admin POST '/api/v1/admin/webhooks/{id}/test' "/api/v1/admin/webhooks/$HID/test"; sleep 6
  check secrets "sealed secrets still usable after rotation (signed webhook.test delivered)" bash -c "grep -q 'webhook.test' $BP_OUT/ev/webhooks.jsonl"
}

for s in "${SECTIONS[@]}"; do echo "== $s"; "s_$s"; done
