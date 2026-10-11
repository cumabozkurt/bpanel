#!/bin/bash
# BPANEL E2E (v1.2.0): App Installer catalogue. Installs EVERY enabled catalogue application through
# the user API into its own sub-directory of one domain, then checks on the real server that
#   - the agent downloaded the pinned archive, verified it and extracted it as the account user,
#   - the database + database user exist and accept the generated password (apps with a database),
#   - nginx + PHP-FPM serve the application's own installer/front page (PHP executed, no source),
#   - "Change primary domain" swaps the primary and an addon domain and both keep serving.
# Runs INSIDE the disposable container as root:  BP_ADMIN_PASS=… BP_TAG=… BP_OUT=… ./apps.sh
cd "$(dirname "$0")"
source ./lib.sh
STATE="$BP_OUT/state.env"; touch "$STATE"; source "$STATE"
save() { for v in "$@"; do sed -i "/^$v=/d" "$STATE"; printf '%s=%q\n' "$v" "${!v}" >> "$STATE"; done; }
ev() { cat > "$BP_OUT/ev/$1"; }
: "${A:=a${BP_TAG}}"; : "${ADOM:=${A}.${BP_TLD}}"; : "${APASS:=AppsPass${RANDOM}z7}"; save A ADOM APASS
AH=/home/$A
SECTIONS=(setup install primary)
[ $# -gt 0 ] && SECTIONS=("$@")

# id -> case-insensitive marker expected in the page the application serves first
declare -A MARK=([wordpress]=wordpress [joomla]=joomla [drupal]=drupal [nextcloud]=nextcloud [matomo]=matomo
  [phpbb]=phpbb [mediawiki]=mediawiki [dokuwiki]=dokuwiki [grav]=grav [backdrop]=backdrop [wondercms]=wondercms
  [mybb]=mybb [opencart]=opencart [mautic]=mautic [omekas]=omeka [fossbilling]=fossbilling)

fetch() { # fetch <host> <path> -> CODE/PAGE (follows same-host redirects)
  local out; out=$(curl -sk --noproxy '*' -m 120 -L --max-redirs 6 --resolve "$1:443:127.0.0.1" --resolve "$1:80:127.0.0.1" \
    -o "$BP_OUT/ev/page.html" -w '%{http_code} %{url_effective}' "https://$1$2")
  PCODE=${out%% *}; PURL=${out#* }
}

s_setup() {
  ROLE_OF_SESSION=admin login admin admin "$BP_ADMIN_USER" "$BP_ADMIN_PASS"; check apps-setup "admin login" code_is 200
  api admin POST /api/v1/admin/packages /api/v1/admin/packages "{\"name\":\"apps-$BP_TAG\",\"disk_mb\":20000,\"bandwidth_mb\":100000,\"max_domains\":5,\"max_subdomains\":5,\"max_aliases\":3,\"max_email\":10,\"max_db\":40,\"max_ftp\":3,\"mail_quota_mb\":200}"
  check apps-setup "package with 40 databases" code_2xx; APKG=$(jqb '.id // .package.id'); save APKG
  api admin POST /api/v1/admin/accounts /api/v1/admin/accounts "{\"username\":\"$A\",\"domain\":\"$ADOM\",\"email\":\"owner@$BP_TLD\",\"password\":\"$APASS\",\"package_id\":$APKG,\"role\":\"user\"}"
  check apps-setup "create account $A" code_is 200; AID=$(jqb '.account.id'); save AID
  ROLE_OF_SESSION=user login ua user "$A" "$APASS"; check apps-setup "user login" code_is 200
  api ua GET /api/v1/user/domains /api/v1/user/domains; ADID=$(echo "$BODY" | jq -r --arg n "$ADOM" '[.. | objects | select(.name? == $n)][0].id'); save ADID
}

s_install() {
  [ -f "$BP_OUT/jars/ua.url" ] || { ROLE_OF_SESSION=user login ua user "$A" "$APASS"; }
  api ua GET /api/v1/user/installer/catalog /api/v1/user/installer/catalog; echo "$BODY" | ev apps-catalog.json
  check apps "catalogue lists 16 installable apps" bash -c "jq -e '[.apps[] | select(.enabled)] | length >= 16' $BP_OUT/ev/apps-catalog.json"
  local ids; ids=$(jq -r '.apps[] | select(.enabled) | .id' "$BP_OUT/ev/apps-catalog.json")
  for id in $ids; do
    local t0=$SECONDS host=$ADOM did=$ADID sub=$id dir=$AH/public_html/$id
    if jq -e --arg i "$id" '.apps[] | select(.id == $i) | .root_only' "$BP_OUT/ev/apps-catalog.json" >/dev/null; then
      # the app's .htaccess assumes the document root: a sub-directory is refused, an own addon domain works
      api ua POST /api/v1/user/installer/install /api/v1/user/installer/install "{\"app\":\"$id\",\"domain_id\":$ADID,\"path\":\"$id\"}"
      check apps "$id: sub-directory install refused (root-only app)" bash -c "[ '$CODE' = 400 ] && echo '$BODY' | grep -q appx_root_only"
      host="$id-$A.$BP_TLD"
      api ua POST /api/v1/user/domains /api/v1/user/domains "{\"name\":\"$host\",\"kind\":\"addon\"}"; check apps "$id: addon domain $host" code_2xx
      api ua GET /api/v1/user/domains /api/v1/user/domains
      did=$(echo "$BODY" | jq -r --arg n "$host" '[.. | objects | select(.name? == $n)][0].id'); dir=$AH/$(echo "$BODY" | jq -r --arg n "$host" '[.. | objects | select(.name? == $n)][0].docroot'); sub=""
    fi
    api ua POST /api/v1/user/installer/install /api/v1/user/installer/install "{\"app\":\"$id\",\"domain_id\":$did,\"path\":\"$sub\"}"
    echo "$BODY" | ev "apps-install-$id.json"
    check apps "$id: install via API (download, verify pinned checksum, extract)" code_is 200 || continue
    local ver dbn dbu dbp; ver=$(jqb .version); dbn=$(jqb '.db_name // ""'); dbu=$(jqb '.db_user // ""'); dbp=$(jqb '.db_password // ""')
    check apps "$id $ver: files owned by $A, no symlinks ($((SECONDS - t0))s)" bash -c \
      "test -f $dir/index.php && [ \$(stat -c %U $dir/index.php) = $A ] && [ -z \"\$(find $dir -type l | head -1)\" ] && [ -z \"\$(find $dir ! -user $A | head -1)\" ]"
    if [ -n "$dbn" ]; then
      if [ "$id" = wordpress ]; then
        check apps "$id: wp-config.php written (0600) with the database" bash -c "grep -q \"'$dbn'\" $dir/wp-config.php && [ \$(stat -c %a $dir/wp-config.php) = 600 ]"
      else
        check apps "$id: database $dbn reachable as $dbu with the shown password" bash -c "mysql -h localhost -u '$dbu' -p'$dbp' -N -e 'SELECT 1' '$dbn' | grep -qx 1"
      fi
    fi
    fetch "$host" "/${sub:+$sub/}"
    cp "$BP_OUT/ev/page.html" "$BP_OUT/ev/apps-page-$id.html"
    check apps "$id: served by nginx/PHP-FPM ($PCODE $PURL)" bash -c \
      "[[ '$PCODE' =~ ^(200|401|403)$ ]] && ! grep -q '<?php' $BP_OUT/ev/apps-page-$id.html && grep -qi '${MARK[$id]}' $BP_OUT/ev/apps-page-$id.html"
  done
  api ua GET /api/v1/user/installer/installs /api/v1/user/installer/installs; echo "$BODY" | ev apps-installs.json
  check apps "installs list has every app" bash -c "[ \$(jq '.installs | length' $BP_OUT/ev/apps-installs.json) -ge $(echo "$ids" | wc -w) ]"
  api ua POST /api/v1/user/installer/install /api/v1/user/installer/install "{\"app\":\"grav\",\"domain_id\":$ADID,\"path\":\"grav\"}"
  check apps "second install into a used directory refused" bash -c "[ '$CODE' = 400 ] && echo '$BODY' | grep -q appx_dest_not_empty"
}

s_primary() {
  local SDOM="shop-$A.$BP_TLD"
  api ua POST /api/v1/user/domains /api/v1/user/domains "{\"name\":\"$SDOM\",\"kind\":\"addon\"}"; check primary "addon domain $SDOM" code_2xx
  api ua GET /api/v1/user/domains /api/v1/user/domains
  local SDR; SDR=$(echo "$BODY" | jq -r --arg n "$SDOM" '[.. | objects | select(.name? == $n)][0].docroot')
  echo "<?php echo 'addon-' . 'ok';" > "$AH/$SDR/index.php"; chown "$A:" "$AH/$SDR/index.php"
  api admin GET /api/v1/admin/accounts/{id}/modify "/api/v1/admin/accounts/$AID/modify"; echo "$BODY" | ev apps-modify.json
  check primary "Modify Account offers the addon domain" bash -c "jq -e --arg d '$SDOM' '.rename_supported and (.addon_domains | index(\$d))' $BP_OUT/ev/apps-modify.json"
  api admin PUT /api/v1/admin/accounts/{id}/modify "/api/v1/admin/accounts/$AID/modify" "{\"primary_domain\":\"$SDOM\"}"; check primary "change primary domain to $SDOM" code_is 200
  api admin PUT /api/v1/admin/accounts/{id}/modify "/api/v1/admin/accounts/$AID/modify" "{\"primary_domain\":\"nothere.$BP_TLD\"}"
  check primary "a non-addon name is refused (422 primary_domain_not_addon)" bash -c "[ '$CODE' = 422 ] && echo '$BODY' | grep -q primary_domain_not_addon"
  api admin GET /api/v1/admin/accounts "/api/v1/admin/accounts?q=$A"
  check primary "account lists $SDOM as primary domain" bash -c "echo '$BODY' | jq -e --arg d '$SDOM' '[.. | objects | select(.primary_domain? == \$d)] | length == 1'"
  api ua GET /api/v1/user/domains /api/v1/user/domains; echo "$BODY" | ev apps-domains-after.json
  check primary "domain kinds swapped (new main, old addon)" bash -c "jq -e --arg n '$SDOM' --arg o '$ADOM' '([.. | objects | select(.name? == \$n)][0].kind == \"main\") and ([.. | objects | select(.name? == \$o)][0].kind == \"addon\")' $BP_OUT/ev/apps-domains-after.json"
  fetch "$ADOM" "/wordpress/"; check primary "old primary still serves its sites ($PCODE)" bash -c "[[ '$PCODE' =~ ^(200|302)$ ]]"
  fetch "$SDOM" "/"; check primary "new primary serves its document root ($PCODE)" bash -c "[ '$PCODE' = 200 ] && grep -q addon-ok $BP_OUT/ev/page.html"
  api admin PUT /api/v1/admin/accounts/{id}/modify "/api/v1/admin/accounts/$AID/modify" "{\"primary_domain\":\"$ADOM\"}"; check primary "swap back to $ADOM" code_is 200
}

for s in "${SECTIONS[@]}"; do "s_$s"; done
echo "apps.sh done: $(grep -c PASS "$RESULTS") PASS, $(grep -c FAIL "$RESULTS") FAIL"
