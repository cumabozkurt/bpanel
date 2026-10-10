# Security (v0.4)

## Firewall (nftables)

BPANEL manages only its own table `inet bpanel`; it never flushes the host ruleset.
Admin UI: **Admin → Firewall** (`/firewall`). API (admin realm, `firewall.read` / `firewall.write`):

| Route | Notes |
|---|---|
| `GET/POST /admin/firewall/rules`, `PUT/DELETE /admin/firewall/rules/{id}` | Draft rules in `fw_rules`. A rule that would match the caller's IP on SSH/panel ports is refused (`fw_lockout`). |
| `POST /admin/firewall/apply` (re-auth) | Renders the ruleset with the **caller's current IP** as protected admin IP, calls agent `netsec.fw.apply`, stores version in `fw_changes` (`pending`), returns `{version, token, deadline}`. |
| `POST /admin/firewall/confirm` | `{version, token}`; token is stored only as sha256. Without confirm before the deadline (default 60 s) the agent restores the previous table; status reconciles to `rolled_back`. |
| `GET /admin/firewall/status`, `GET /admin/firewall/history` | Support probe (`unsupported` when nft is missing), pending change, current version. |
| `POST /admin/firewall/rollback/{version}` (re-auth) | Re-applies a stored version with the same confirm window. |
| `GET/POST /admin/firewall/blocks`, `DELETE /admin/firewall/blocks/{id}` | Temporary blocks (element timeout in the kernel, `fw_blocks` in DB). A background loop deletes expired rows every minute and publishes `netsec.block` events (`add`/`remove`/`expired`). |

Reseller and auditor roles get 403 on every mutation.

## WAF

BPANEL does **not** embed a WAF engine (Coraza was evaluated: Apache-2.0 but a large
dependency; not added). It manages ModSecurity/Coraza-compatible (SecLang) per-domain
includes for the web server already in use and loads the OWASP Core Rule Set from the
distribution package.

What must be installed on the host:

| Distro | Packages |
|---|---|
| Debian / Ubuntu (nginx) | `libnginx-mod-http-modsecurity` (libmodsecurity3 connector) and `modsecurity-crs`; copy `/etc/modsecurity/modsecurity.conf-recommended` to `/etc/modsecurity/modsecurity.conf` |
| AlmaLinux / Rocky (Apache) | `mod_security` (mod_security2) and `mod_security_crs` (EPEL/AppStream) |

ModSecurity (libmodsecurity, mod_security2) and the OWASP CRS are Apache-2.0 and run
inside the web server as separate programs; nothing is linked into the BPANEL binary.

Probe (agent `netsec.waf.status`, fixed paths, never faked): nginx module
`/usr/lib/nginx/modules/ngx_http_modsecurity_module.so` (or `/usr/lib64/...`), Apache
`mod_security2.so` under `/usr/lib/apache2/modules` or `/usr/lib64/httpd/modules`, CRS
rules in `/usr/share/modsecurity-crs/rules` or `/usr/share/mod_modsecurity_crs/rules`,
`crs-setup.conf`, and (nginx) `modsecurity.conf`. Anything missing → `not_installed`
with the list of missing parts; `netsec.waf.apply` then writes nothing.

Per domain (`PUT /admin/waf/{domain}`, `waf.write`): mode `audit` (default,
`SecRuleEngine DetectionOnly`), `block` (`On`) or `off`; exclusions are
`SecRuleRemoveById` with **numeric IDs only** (1..9999999, max 256, anything else →
`waf_invalid`). Each apply increments the domain's version (`waf_domains`) and is kept
in `waf_changes`. (`waf_rules` from migration 0008 only allows audit|block, so the
per-domain state lives in the new tables of `0008b_netsec_waf.sql`.)

Apply (agent `netsec.waf.apply`): writes `/etc/bpanel/waf/<domain>.conf` (rules) and
the server snippet (nginx `/etc/nginx/bpanel-waf.d/<domain>.conf` with
`modsecurity on; modsecurity_rules_file …;`, Apache `<conf>/bpanel-waf.d/<domain>.conf`
inside `<IfModule security2_module>`), runs `/usr/sbin/nginx -t` or
`/usr/sbin/apache2ctl|apachectl configtest` (fixed argv, 30 s timeout) and **restores
the previous files** if the test fails (`waf_configtest_failed`). On Apache the base
config and CRS are loaded globally by mod_security2, so the vhost include only sets
the engine mode and exclusions.

**Vhost wiring (v0.4 part C):** the vhost templates carry a conditional WAF include
(template fields `WAFInclude` / `ApacheWAFInclude`; empty renders nothing). The agent
sets them in `RenderVhost` only when the per-domain snippet exists (mode audit/block;
mode off deletes the snippet and rules file) and, for nginx, the ModSecurity module is
installed — nginx rejects an unknown `modsecurity` directive, so a missing module renders
nothing. nginx: `include "/etc/nginx/bpanel-waf.d/<domain>.conf";` inside the serving
`server` block; Apache: `IncludeOptional "<conf dir>/bpanel-waf.d/<domain>.conf"`
(snippet wrapped in `<IfModule security2_module>`). `netsec.waf.apply` receives the
domain's vhost (built by the API exactly like account provisioning; alias domains are
served by their parent and get none) and re-applies it through the normal vhost apply
path (render → `nginx -t`/`apachectl configtest` → reload, vhost files rolled back on
failure); on failure the previous WAF files are restored too and `waf_configtest_failed`
is returned. Success returns `wired:true`. Without a vhost the old check remains
(`wired` only if the existing vhost already references the snippet, else
`vhost_not_wired`). Not verified against a real nginx/Apache with ModSecurity (none in
the sandbox); verified with fake binaries in `internal/agent/netsec_waf_test.go`.
No installer flag was added (not trivial: package names differ per distro and Debian
needs the recommended config copied).

## Secret providers (v0.4)

`secrets.SecretStore` has two implementations. Both are free and open source.

| Provider | Where values live | Seal/Open (column envelope) | Rotation |
|---|---|---|---|
| `local` (default) | `secrets` table, AES-256-GCM under a 32-byte master key in `/etc/bpanel/secret.key` (0600) | AES-256-GCM, `bpsec:v1:<kid>:…` | `Rotate` re-encrypts every row (keyring file keeps rotation crash-safe) |
| `openbao` | [OpenBao](https://openbao.org) (MPL-2.0, the community fork of Vault) KV v2: `<kv_mount>/data/<prefix>/<name>` | Transit with a **derived** key; aad is passed as Transit `context`; `bpsec:v1:obt:…` | `Rotate` rotates the Transit key (new Seals use it, old versions still open; `Reseal` rewraps). KV barrier rotation (`sys/rotate`) stays an OpenBao operator task |

**Selecting a provider.** If `api.json` has `"secrets": {"provider": "local"|"openbao", "openbao_config": "/etc/bpanel/openbao.json"}`, that wins. Otherwise the `secrets_provider` setting written by the migrate tool is used. The default is `local`. A misconfigured OpenBao **never** falls back to local, because writes would go to the wrong place. Instead the store reports `unavailable` with a reason (API `secrets_unavailable` / `secret_backend_unavailable`).

**OpenBao connection** (`/etc/bpanel/openbao.json`, refused unless mode 0600):

```json
{"addr":"https://bao.internal:8200","ca_cert_file":"/etc/bpanel/openbao-ca.pem",
 "pin_sha256":"<optional hex sha256 of the server SPKI>",
 "role_id":"…","secret_id":"…","kv_mount":"secret","prefix":"bpanel",
 "transit_mount":"transit","transit_key":"bpanel","timeout_sec":10,"retries":3}
```

* **Auth**: AppRole login. The token is renewed (`auth/token/renew-self`) once it enters the last third of its TTL. If renewal fails, or a request gets 403 (for example a revoked token), BPANEL logs in again once.
* **TLS**: `https` is required (`allow_insecure_http` exists for loopback tests only). Only the configured CA is trusted, never the system pool. An optional SPKI pin also binds the server key. Redirects are not followed.
* **Robustness**: there is a per-request timeout. Network errors, 429 and 5xx are retried with backoff. 4xx errors are not retried.
* **No leaks**: errors carry only OpenBao's `errors[]` text, passed through `redact`. Tokens, secret_id and values never appear in errors, logs or `Status()`.
* **Least-privilege policy** (tested against a real server):

```hcl
path "secret/data/bpanel/*"       { capabilities = ["create","read","update"] }
path "secret/metadata/bpanel"     { capabilities = ["list"] }
path "secret/metadata/bpanel/*"   { capabilities = ["read","list","delete"] }
path "transit/encrypt/bpanel"     { capabilities = ["update"] }
path "transit/decrypt/bpanel"     { capabilities = ["update"] }
path "transit/keys/bpanel/rotate" { capabilities = ["update"] }
```

**Migration.** `bpanel secrets migrate --to openbao` (and `--to local` to go back) follows these steps:

1. Ping the destination: health check and login.
2. Copy every named secret.
3. Read each one back and compare it byte-for-byte.
4. Only if all of them match, set `secrets_provider`. Restart `bpanel-api` to apply.

The source is never modified, so rollback is just migrating back. `bpanel secrets status` prints the active provider and its status, never values. Columns sealed by the local provider before migration still open under `openbao` through its `Legacy` fallback, as long as `/etc/bpanel/secret.key` is kept. Re-sealing them into Transit is a follow-up.

**Verified (2026-10-10)**:

* Unit tests run against an in-process fake of the OpenBao API (`internal/secrets/openbao_test.go`). They cover:
  * the conformance suite
  * retry on 503
  * re-login after token revocation
  * renewal timing
  * bad credentials without leaks
  * TLS: the pinned CA is accepted, while a foreign CA, a wrong SPKI pin, and https without a CA are all refused
  * config mode 0600
  * local→openbao→local migration, including the verify-failure path
* A real test (`go test -tags openbao`, `BPANEL_BAO=…`) ran OpenBao v2.7.1 linux/arm64 (SHA-256 checked against the release `checksums.txt`) in `server -dev -dev-tls`. It checked:
  * AppRole, Transit and the policy above
  * the same suite over TLS with only the dev CA trusted
  * real renew-self
  * that the policy blocks paths outside the prefix
  * migrating 20 secrets local→OpenBao and back
* **Not verified**:
  * a production (non-dev) OpenBao with Raft storage and auto-unseal
  * namespaces
  * the `bpanel secrets migrate` CLI end-to-end, since it reads the fixed `/etc/bpanel/api.json`; its logic `api.MigrateSecrets` reuses the tested `secrets.Migrate`

There is no UI for switching providers. The existing Secrets status card shows `Status()`, including provider, addr and authenticated.
