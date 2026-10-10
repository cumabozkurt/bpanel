# Plugins (v0.4, clusterx)

BPanel plugins are **signed, declarative bundles**. A plugin can ship static web
pages and subscribe to internal events via webhooks. It can **not** run code on
the server, add agent actions or touch the filesystem outside its own directory.
Everything is free software (Go stdlib `crypto/ed25519`, `archive/tar`).

## Archive layout

```
plugin.json        manifest (strict JSON, unknown fields rejected)
plugin.sig         base64 ed25519 signature
ui/...             static files (html, css, js, images)
```

Nothing else is accepted. Limits: 8 MiB compressed, 32 MiB unpacked, 8 MiB per
file, 512 entries. Extraction happens **in memory**; regular files and
directories only — symlinks, hard links, devices and FIFOs are rejected, as are
absolute paths, `..`, backslashes, NUL bytes and characters outside
`[A-Za-z0-9._-]` in each path segment. The agent re-runs the same checks before
writing (defence in depth) and installs atomically into
`/usr/local/bpanel/plugins/<name>` (staging dir + rename, `O_EXCL|O_NOFOLLOW`).

## Manifest

| field | rule |
|---|---|
| `name` | `^[a-z][a-z0-9-]{1,39}$` (also the directory name) |
| `version` | semantic `1.2.3[-tag]` |
| `author`, `license` | required; license is an SPDX expression |
| `permissions` | subset of the fixed list below |
| `ui_entry` | file below `ui/` (needs `ui.page`) |
| `agent_actions` | subset of the read-only allowlist (needs `agent.read`) |
| `hooks` | ≤ 8 × `{events: [...], url}` (needs `events.subscribe`) |

Permissions (fixed, `internal/clusterx/plugin.go`):

* `ui.page` — show its own page in a sandboxed iframe.
* `events.subscribe` — receive the listed events as HMAC-signed webhooks.
* `agent.read` — declare existing read-only agent methods it relies on:
  `system.info`, `service.status`, `system.updates.status`, `appx.runtimes`,
  `pg.status`, `shield.status`, `f2b.status`. *There is currently no plugin
  runtime that calls them; the declaration is reviewed and stored so a future
  declarative action surface can enforce it. Unknown methods are rejected.*

## Signature

`plugin.sig` = base64(ed25519.Sign(priv, payload)) where payload is
`"bpanel-plugin-v1\n"` followed by `"<sha256 hex>  <path>\n"` for every file
except `plugin.sig`, sorted by path. Adding, removing or changing any file
invalidates the signature. The admin manages the **trusted keys** list
(Plugins → Trusted signing keys); with no key nothing can be installed.

Tooling: `go run ./examples/plugins/sign keygen -out mykey` and
`go run ./examples/plugins/sign pack -key mykey -dir examples/plugins/hello -out hello.tar.gz`.

## Lifecycle (admin only, RBAC `server.read`/`server.write`)

| API | notes |
|---|---|
| `GET /admin/plugins` | plugins, trusted keys, permission catalogue |
| `POST /admin/plugins/inspect` `{archive: base64}` | safe extraction + manifest + signature → capability review, nothing written |
| `POST /admin/plugins` | same checks, then agent `plugin.install`; installed **disabled**; requires recent re-auth |
| `POST /admin/plugins/{name}/enable` `{enabled}` | enabling re-validates the manifest and creates one `webhooks` row per hook (`plugin:<name>:<n>`, URL passes the webhook SSRF guard, secret in the SecretStore); disabling deletes them |
| `DELETE /admin/plugins/{name}` | agent `plugin.remove` (refuses symlinks) + hooks removed |
| `POST /admin/plugin-keys`, `DELETE /admin/plugin-keys/{id}` | trusted keys (re-auth for adding) |
| `GET /admin/plugins/{name}/ui/*` | static files of an **enabled** plugin, served with `Content-Security-Policy: sandbox allow-scripts allow-forms; connect-src 'none'; frame-ancestors 'self'` → opaque origin, no cookies, no fetch to the panel API |

An enabled plugin cannot be overwritten in place (`plugin_exists`): disable, then upload the new version.
Every install / enable / disable / remove / key change is audited.

## Verified / not verified

* Verified by tests (`internal/clusterx`, `internal/agent`, `internal/api`): tar traversal, absolute paths, symlink, hard link, device, FIFO rejection; size limits; bad / untrusted / tampered / missing signatures; permission outside the allowlist; unknown agent action; atomic install + upgrade + removal in a temp root; hook registration and removal; sandbox headers; disabled plugins not served.
* Not verified: rendering inside a real browser (CSP behaviour relies on standard browser semantics); installation under the real `/usr/local/bpanel/plugins` (tests use a temp root).
