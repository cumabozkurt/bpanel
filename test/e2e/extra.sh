#!/bin/bash
# BPANEL E2E supplement (v1.1.0): rows that the main suites did not drive yet.
#   ruby  - Application Manager with a Ruby app (cPanel "Ruby Gems / Ruby on Rails" row)
#   nsdns - Track DNS NS lookup of the own zone, with the system resolver pointed at the
#           server's own PowerDNS for the duration of the check (the container's upstream
#           resolver answers no NS queries; on a real host the zone is delegated publicly).
# Runs INSIDE the disposable container as root:  BP_ADMIN_PASS=… BP_TAG=… BP_OUT=… ./extra.sh
cd "$(dirname "$0")"
source ./lib.sh
STATE="$BP_OUT/state.env"; touch "$STATE"; source "$STATE"
save() { for v in "$@"; do sed -i "/^$v=/d" "$STATE"; printf '%s=%q\n' "$v" "${!v}" >> "$STATE"; done; }
ev() { cat > "$BP_OUT/ev/$1"; }
: "${X:=x${BP_TAG}}"; : "${XDOM:=${X}.${BP_TLD}}"; : "${XPASS:=XtraPass${RANDOM}z4}"; save X XDOM XPASS
XH=/home/$X
SECTIONS=(setup ruby nsdns cleanup)
[ $# -gt 0 ] && SECTIONS=("$@")
reauth() { api admin POST /api/v1/account/reauth /api/v1/account/reauth "$(jq -nc --arg p "$BP_ADMIN_PASS" '{password:$p}')"; }

s_setup() {
  ROLE_OF_SESSION=admin login admin admin "$BP_ADMIN_USER" "$BP_ADMIN_PASS"; check x-setup "admin login" code_is 200
  api admin GET /api/v1/admin/packages /api/v1/admin/packages; PKG=$(jqb '[.. | objects | select(.disk_mb? != null)][0].id')
  api admin POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"$X\",\"domain\":\"$XDOM\",\"email\":\"owner@$BP_TLD\",\"password\":\"$XPASS\",\"package_id\":$PKG,\"role\":\"user\"}"
  check x-setup "create account $X" code_is 200; XID=$(jqb '.account.id'); save XID
  ROLE_OF_SESSION=user login ux user "$X" "$XPASS"; check x-setup "user login" code_is 200
  api ux GET /api/v1/user/domains /api/v1/user/domains; XDID=$(echo "$BODY" | jq -r --arg n "$XDOM" '[.. | objects | select(.name? == $n)][0].id'); save XDID
}

s_ruby() {
  api admin GET /api/v1/admin/apps/settings /api/v1/admin/apps/settings; echo "$BODY" | ev x-apps-settings.json
  check ruby "Ruby runtime detected" bash -c "jq -e '.runtimes[] | select(.runtime==\"ruby\")' $BP_OUT/ev/x-apps-settings.json"
  local rv; rv=$(jq -r '[.runtimes[] | select(.runtime=="ruby") | .version][0]' "$BP_OUT/ev/x-apps-settings.json")
  mkdir -p "$XH/rubyapp"; cat > "$XH/rubyapp/app.rb" <<'RB'
require 'socket'
server = TCPServer.new('127.0.0.1', Integer(ENV.fetch('PORT')))
loop do
  c = server.accept
  while (l = c.gets) && l != "\r\n"; end
  b = "hello from ruby e2e #{RUBY_VERSION}"
  c.write "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: #{b.bytesize}\r\nConnection: close\r\n\r\n#{b}"
  c.close
end
RB
  chown -R "$X:$X" "$XH/rubyapp"
  api ux POST /api/v1/user/apps /api/v1/user/apps "{\"name\":\"rubye2e\",\"runtime\":\"ruby\",\"version\":\"$rv\",\"root\":\"rubyapp\",\"startup\":\"app.rb\",\"domain_id\":$XDID,\"url_path\":\"/ruby\"}"
  check ruby "create Ruby app (runtime ruby $rv)" code_2xx; echo "$BODY" | ev x-ruby-create.json
  local aid; aid=$(jqb '.id // .app.id')
  api ux POST '/api/v1/user/apps/{id}/ctl' "/api/v1/user/apps/$aid/ctl" '{"action":"start"}'; check ruby "start (systemd bpanel-app@ unit)" code_2xx; sleep 4
  check ruby "unit carries GEM_HOME/RACK_ENV (Ruby environment)" bash -c "systemctl cat 'bpanel-app@*' 2>/dev/null | grep -q 'RACK_ENV=production'"
  check ruby "app reachable through the domain (/ruby)" bash -c "for i in 1 2 3 4 5; do curl -s --noproxy '*' -H 'Host: $XDOM' http://127.0.0.1/ruby/ | grep -q 'hello from ruby e2e' && exit 0; sleep 2; done; exit 1"
  check ruby "app runs as the account user" bash -c "ps -o user= -C ruby | grep -qx '$X'"
  api ux POST '/api/v1/user/apps/{id}/ctl' "/api/v1/user/apps/$aid/ctl" '{"action":"stop"}'; check ruby "stop" code_2xx
  check ruby "process gone after stop" bash -c "sleep 2; ! ps -o user= -C ruby | grep -qx '$X'"
  api ux DELETE '/api/v1/user/apps/{id}' "/api/v1/user/apps/$aid"; check ruby "delete" code_2xx
}

s_nsdns() {
  cp -a /etc/resolv.conf /tmp/resolv.conf.e2e-saved
  printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
  sleep 1
  api ux GET /api/v1/user/dns-lookup "/api/v1/user/dns-lookup?host=$XDOM&type=NS"; echo "$BODY" | ev x-ns-lookup.json
  cat /tmp/resolv.conf.e2e-saved > /etc/resolv.conf
  check tdns "dns lookup NS of the own zone (resolver = own PowerDNS)" bash -c "[ $CODE = 200 ] && echo '$BODY' | grep -qi 'ns1\\|ns2'"
}

s_cleanup() {
  reauth; api admin DELETE '/api/v1/admin/accounts/{id}' "/api/v1/admin/accounts/$XID"; check x-setup "terminate $X" code_2xx
}

for s in "${SECTIONS[@]}"; do echo "== $s"; "s_$s"; done
