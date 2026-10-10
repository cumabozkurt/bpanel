#!/bin/bash
# BPANEL e2e suite — shared helpers. Source this; do not run it.
# Requires: bash, curl, jq, sudo (root checks), dig, swaks, mysql client, lftp, sshpass, openssl, python3, zip/unzip.
set -u
: "${BP_HOST:=127.0.0.1}"
: "${BP_ADMIN_PORT:=2087}"
: "${BP_USER_PORT:=2083}"
: "${BP_ADMIN_USER:=bpadmin}"
: "${BP_ADMIN_PASS:?set BP_ADMIN_PASS (installer prints it once)}"
: "${BP_OUT:=$(pwd)/out}"
: "${BP_TAG:=e2e$(date +%H%M)}"           # unique suffix for usernames/domains
: "${BP_TLD:=e2e.test}"                    # test zone suffix (never a real domain)
: "${BP_DNS:=127.0.0.1}"                   # authoritative server to query with dig
: "${BP_MAIL_HOST:=127.0.0.1}"
ADMIN_URL="https://$BP_HOST:$BP_ADMIN_PORT"
USER_URL="https://$BP_HOST:$BP_USER_PORT"
mkdir -p "$BP_OUT/jars" "$BP_OUT/ev"
RESULTS="$BP_OUT/results.tsv"; COVER="$BP_OUT/coverage.tsv"
[ -f "$RESULTS" ] || printf 'id\tstatus\tarea\tcheck\tdetail\n' > "$RESULTS"
[ -f "$COVER" ] || printf 'method\troute\trole\tcode\n' > "$COVER"
CURL=(curl -sk --noproxy '*' -m 600)
N=${N:-0}

# api <session> <METHOD> <route-template> <path> [json-body]
#   session = name of a cookie jar created by login; sets CODE, BODY.
api() {
  local s="$1" m="$2" tpl="$3" p="$4" body="${5-}" url csrf
  url=$(cat "$BP_OUT/jars/$s.url"); csrf=$(cat "$BP_OUT/jars/$s.csrf" 2>/dev/null || true)
  local args=(-X "$m" -b "$BP_OUT/jars/$s.jar" -c "$BP_OUT/jars/$s.jar" -H "X-CSRF-Token: $csrf" -H "Origin: $url" -w '\n%{http_code}')
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
  local out; out=$("${CURL[@]}" "${args[@]}" "$url$p")
  CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"
  printf '%s\t%s\t%s\t%s\n' "$m" "$tpl" "$(cat "$BP_OUT/jars/$s.role")" "$CODE" >> "$COVER"
  printf '%s %s %s -> %s %s\n' "$s" "$m" "$p" "$CODE" "${BODY:0:600}" >> "$BP_OUT/ev/http.log"
}
# raw multipart/GET helpers record coverage too
cover() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$COVER"; }

# login <session> <admin|user> <username> <password> [totp]
login() {
  local s="$1" realm="$2" u="$3" pw="$4" t="${5-}" url
  [ "$realm" = admin ] && url=$ADMIN_URL || url=$USER_URL
  echo "$url" > "$BP_OUT/jars/$s.url"; : > "$BP_OUT/jars/$s.jar"; echo "${ROLE_OF_SESSION:-$s}" > "$BP_OUT/jars/$s.role"
  local body; body=$(jq -nc --arg u "$u" --arg p "$pw" --arg t "$t" '{username:$u,password:$p} + (if $t=="" then {} else {totp:$t} end)')
  local out; out=$("${CURL[@]}" -X POST -c "$BP_OUT/jars/$s.jar" -H 'Content-Type: application/json' -H "Origin: $url" -w '\n%{http_code}' --data-binary "$body" "$url/api/v1/auth/login")
  CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"
  cover POST /api/v1/auth/login "$(cat "$BP_OUT/jars/$s.role")" "$CODE"
  echo "$BODY" | jq -r '.csrf // empty' 2>/dev/null > "$BP_OUT/jars/$s.csrf"
  printf '%s LOGIN %s@%s -> %s %s\n' "$s" "$u" "$realm" "$CODE" "${BODY:0:300}" >> "$BP_OUT/ev/http.log"
}

# check <area> <description> <test-command...>   (records PASS/FAIL)
check() {
  local area="$1" desc="$2"; shift 2
  N=$((N+1)); local id; id=$(printf 'T%03d' "$N")
  local detail
  if detail=$( { "$@"; } 2>&1 ); then
    printf '%s\tPASS\t%s\t%s\t%s\n' "$id" "$area" "$desc" "$(echo "$detail" | tr '\t\n' '  ' | cut -c1-300)" >> "$RESULTS"; echo "PASS $id [$area] $desc"
  else
    printf '%s\tFAIL\t%s\t%s\t%s\n' "$id" "$area" "$desc" "$(echo "$detail" | tr '\t\n' '  ' | cut -c1-300)" >> "$RESULTS"; echo "FAIL $id [$area] $desc :: $(echo "$detail" | tail -3 | tr '\n' ' ' | cut -c1-300)"
  fi
}
skip() { N=$((N+1)); printf 'T%03d\tSKIP\t%s\t%s\t%s\n' "$N" "$1" "$2" "${3-}" >> "$RESULTS"; echo "SKIP [$1] $2 ${3-}"; }

code_is() { [ "$CODE" = "$1" ] || { echo "HTTP $CODE (want $1): ${BODY:0:400}"; return 1; }; }
code_2xx() { [[ "$CODE" == 2* ]] || { echo "HTTP $CODE: ${BODY:0:400}"; return 1; }; }
code_4xx() { [[ "$CODE" == 4* ]] || { echo "HTTP $CODE (want 4xx): ${BODY:0:400}"; return 1; }; }
jqb() { echo "$BODY" | jq -r "$@"; }
sudo_() { "$@"; }
# wait_for <seconds> <cmd...>
wait_for() { local t=$1; shift; for _ in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; "$@"; }
totp_now() { python3 - "$1" <<'P'
import sys,base64,hmac,hashlib,struct,time
s=sys.argv[1].upper(); s+='='*((8-len(s)%8)%8)
k=base64.b32decode(s); c=struct.pack('>Q',int(time.time())//30)
h=hmac.new(k,c,hashlib.sha1).digest(); o=h[-1]&15
print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))
P
}
