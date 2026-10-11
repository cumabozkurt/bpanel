# Applications: Application Manager, App Installer, WordPress Toolkit (v0.4 appx)

All free and open source. No paid installer (Softaculous/Installatron) or paid
runtime selector (CloudLinux) is used; this is the free subset implemented
natively.

## Application Manager (Node.js / Python) — `/apps`
* Per-account apps: name, runtime (`node`|`python`), major version chosen from
  the binaries the agent **detects** (`/usr/bin/node`, `/usr/bin/python3*`,
  `/opt/bpanel/runtimes/{node,python}-*/bin/…`), app root and startup file
  (both relative to the home; `..`, absolute paths and metacharacters are
  refused by `appx.CleanRel`), env vars (`PORT`, `LD_*`, `NODE_OPTIONS`,
  `PYTHONPATH` reserved), optional domain + URL path.
* Port: lowest free port in the per-server range stored in `appx_settings`
  (`port_lo`/`port_hi`, default 30000-30999, admin `PUT /admin/apps/settings`);
  `appx_apps.port` is UNIQUE so concurrent creates retry.
* Service: `bpanel-app@<id>.service` = hardened template unit
  (NoNewPrivileges, ProtectSystem=strict, PrivateTmp/Devices, empty
  CapabilityBoundingSet, RestrictAddressFamilies, `TemporaryFileSystem=/home:ro`
  so other homes are invisible) + per-app drop-in (`User=`/`Group=` account,
  `Slice=bpanel-u-<account>.slice`, `BindPaths=` own home, `ReadWritePaths=` app
  root, `ExecStart=<runtime> <startup>`, `EnvironmentFile=/etc/bpanel/apps/<id>.env`
  0600 root). Python uses `<root>/.venv/bin/python` when it exists.
* **No systemd as PID 1 → start/stop/restart/logs return `appx_unsupported`**
  (API + UI banner). The unit files are still written so the app starts once
  the host runs systemd. Nothing is faked.
* `npm install --omit=dev` / `python -m venv .venv && .venv/bin/pip install -r
  requirements.txt` run **as the account** inside its slice (systemd-run, or the
  agent's `cage-exec` without systemd), env cleared, 10 min timeout, output tail
  returned.
* Public URL: nginx `location ^~ /path/ { proxy_pass http://127.0.0.1:<port>/; }`
  (+ websocket headers, X-Forwarded-*, X-Forwarded-Prefix) in
  `/etc/nginx/bpanel-appx.d/<domain>.conf`, included by the vhost template
  (`AppXInclude`, same pattern as WAFInclude/WebXInclude). URL path `/` replaces
  the site's `location /` via the template field `AppXRootPort`. Written in the
  vhost transaction: nginx config test, rollback on failure. Suspended and
  redirect vhosts never proxy. State is root-owned
  (`/var/lib/bpanel/appx/proxy/<domain>.json`) and bound to the account.

## App Installer — `/installer`
* Catalogue in Go (`internal/appx/catalog.go`), 16 enabled applications with
  pinned URLs + checksums (sources in the file header): WordPress 7.1.3,
  Joomla 6.1.4, Drupal 11.4.9, Nextcloud 35.0.1, Matomo 5.14.1, phpBB 3.3.19,
  MediaWiki 1.46.2, DokuWiki 2026-07-14c, Grav 2.2.6 (+Admin), Backdrop CMS
  1.35.1, WonderCMS 3.6.0, MyBB 1.8.41, OpenCart 4.1.0.4, Mautic 7.2.1,
  Omeka S 4.2.1 and FOSSBilling 0.8.8 (v1.2.0). Archives are tar.gz, tar.bz2,
  tgz or zip. Root-only apps (e.g. FOSSBilling) refuse a sub-directory install.
  The agent only downloads URLs from this table.
* Flow: API creates DB + DB user + grant via the existing database code
  (package limits apply) → agent downloads to a root-only temp dir, verifies
  sha256 (+ sha1 for WordPress) in constant time **before** extraction → extracts
  into an `os.Root` of the destination as the account uid/gid; links (except a link to a regular file of the same
  archive, written as a copy), devices, absolute and `..` entries are refused; size/entry caps. The destination must be
  empty apart from the panel's default page (renamed to `index.html.bpanel-bak`,
  never deleted). Any failure drops the DB/user it created.
* WordPress: `wp-config.php` (0600, owner = account) with DB settings and 8 salts
  from `crypto/rand`, `DISALLOW_FILE_EDIT`. Other apps: the DB password is shown
  once to finish the app's own web installer; it is never stored.

## WordPress Toolkit — `/wordpress`
* Lists WordPress installs, reads `$wp_version`, toggles maintenance mode by
  writing/removing `.maintenance` (`<?php $upgrading = time(); ?>`, the file
  WP-CLI writes), core update via WP-CLI as the account
  (`php wp-cli.phar core update`) when the admin installed WP-CLI
  (`POST /admin/apps/wpcli`, official phar verified against its published
  sha512); otherwise `appx_wpcli_missing` / `appx_php_cli_missing`.

## Verified vs not verified
* Verified in tests: path containment, archive escape/symlink refusal, checksum
  mismatch rejection (no files written), port allocation, URL-path conflicts,
  ownership of extracted files + wp-config mode, cross-account refusal (agent +
  API), unit/drop-in/env rendering, proxy include + root proxy rendering, agent
  `appx_unsupported` without systemd, DB rollback on install failure.
* Verified against the network: the four pinned checksums (2026-10-10).
* **Not verified on a real host**: starting units under systemd (sandbox PID 1
  is not systemd), real nginx config test, real npm/pip runs, real WP-CLI update.

## Limits / follow-ups
* No admin UI page yet for the port range / WP-CLI install (API only).
* No per-app resource limits beyond the account slice; no Ruby/PHP-app manager.
* Catalogue versions need a periodic bump (a new pin + checksum per release).
