# Web extras (v0.4 "webx")

User-panel tools: **Directory Privacy, Hotlink Protection, Error Pages, MIME Types, IP Blocker**.
UI: `/web/privacy`, `/web/hotlink`, `/web/error-pages`, `/web/mime`, `/web/ip-blocker` (one page, `WebExtras.svelte`).
Everything is free/open-source: nginx, Apache httpd, Go stdlib, `golang.org/x/crypto/bcrypt` (BSD-3, already a dependency). No new dependency.

## Design
- `internal/webx`: types, strict validation (`Config.Normalize`), renderers. Allowlists: paths `[A-Za-z0-9._~-]` segments (no dot-folders, no `..`, site root refused), realm `[A-Za-z0-9 ._-]{1,64}`, users `[A-Za-z0-9._-]{1,32}`, bcrypt hash regex, domains via `validate.Domain`, extensions `[a-z0-9]{1,16}`, MIME `top/sub` with top in {application,audio,font,image,model,text,video}, script extensions (php, phtml, cgi, …) refused, IPs/CIDRs via `net/netip` (canonicalised, /0 refused, zones refused), error codes {400,401,403,404,500,502,503}, ≤64 KiB per page. The renderer re-checks every token with `validate.ConfigSafe` (defence in depth).
- Agent `webx.apply` (`internal/agent/webx.go`, gated on `user`, R2-WB-1): validates, refuses a domain registered to another account, stores state under `/var/lib/bpanel/webx/<domain>/` (config.json 0600 incl. owning user; `htpasswd/<n>` 0640 root:web-group; `errors/<code>.html` 0644) and re-applies the vhost through `vhostApply`. `vhostApply` renders ONE nginx include `/etc/nginx/bpanel-webx.d/<domain>.conf` and ONE Apache include `<apache conf>/bpanel-webx.d/<domain>.conf` inside the same file transaction as the vhost, runs the config test, rolls everything back on failure; webx.apply then restores the previous state dir and answers `webx_configtest_failed`.
- Templates: new fields `WebXInclude` / `ApacheWebXInclude` (pattern of `WAFInclude`); empty → nothing rendered, so existing vhosts are byte-identical (template Version not bumped). Suspended/redirect vhosts never include extras. State whose stored user differs from the vhost user is ignored (a re-added domain never inherits).
- nginx: `deny` (server level), `error_page` + `location ^~ /.bpanel-errors/ { internal; alias … }`, MIME via `location ~* \.ext$ { types { } default_type …; }` (hotlink check repeated inside when the ext is also protected), hotlink via `valid_referers` (+ `none blocked` when direct requests are allowed), privacy via `location ^~ "/dir/" { auth_basic …; }` with PHP (nginx mode) or proxy to Apache (nginx-apache mode) and dotfile deny nested.
- Apache: `Alias`+`ErrorDocument`, `AddType`, `Require not ip` in `<RequireAll>`, mod_rewrite hotlink rules, `<Directory>` AuthType Basic.
- API (`internal/api/webx.go`), all under the user realm, domain resolved with `ownDomain` (own account only, aliases refused): `GET /api/v1/user/web/extras`, `GET /api/v1/user/web/{id}/extras`, `PUT …/{id}/privacy|hotlink|error-pages|mime|ip-blocker`. Passwords are hashed with bcrypt cost 10 (`$2y$`) in the API; plaintext never reaches the agent or DB; hashes are never returned. DB row (`webx_domains`, migration 0011, cascades with the domain) is written only after the agent succeeded. Audit: `webx.<section>`.
- Dev mock agent validates exactly like the real agent and writes nothing.

## Verified
Unit/golden tests (`internal/webx`), injection tests (newline, `;`, braces, quotes, `$`, `#`, `\`) at validation and render level, template conditional include test, agent apply/rollback/ownership/suspended/clear test with a failing config test, API test (ownership 404 for another account, hashes not leaked, invalid input never reaches the agent, failed apply not persisted), mock agent test.

## Not verified
- Not run against a real nginx/Apache (`nginx -t` with the rendered include). Fake config test only.
- bcrypt in nginx `auth_basic_user_file` relies on the system `crypt()` (libxcrypt on Debian 12 / Ubuntu 22.04+ / EL9 supports `$2y$`); older glibc-only systems would not.
- Apache `Require not ip` only matches real clients with mod_remoteip; nginx in front enforces the deny list in every mode.

## Limits
Site root cannot be protected (would also block ACME). Up to 50 protected dirs × 50 users, 100 MIME types, 500 deny entries. A `^~` protected directory takes precedence over hotlink/MIME regex locations for files inside it (nginx). Error pages live outside the docroot (tenant cannot tamper; served via an internal alias) instead of in the docroot.
