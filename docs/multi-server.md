# Multi-server (msrv, spec §16)

BPANEL can manage remote nodes from one panel. The panel ↔ node channel is
mutually authenticated TLS 1.3; there is no unauthenticated network root API.
Default behaviour is unchanged: the agent only listens on its unix socket
unless `remote_listen` is set.

## Design
- **Panel CA** (`internal/msrv/ca.go`): ECDSA P-256 self-signed CA, stdlib
  `crypto/x509`, created on first use. Key + cert live only in the panel
  SecretStore (`msrv/ca.key`, `msrv/ca.crt`, AES-256-GCM local provider). A
  half-present CA is never silently replaced. The panel's own client cert
  (`bpanel://panel`) is issued from it and renewed 30 days before expiry (old
  serial revoked).
- **Enrolment**: admin `POST /api/v1/admin/servers {name,address,roles}` (step-up
  auth) → one-time token `bpj_…` (32 random bytes; only its sha256 is stored;
  15 min expiry; single use, claimed atomically; a new token supersedes unused
  ones). On the node: `BPANEL_JOIN_TOKEN=… bpanel-agent join --panel https://panel:2083
  [--panel-ca file | --panel-fingerprint sha256hex]`. The node generates its key
  (never leaves the node), sends a CSR to `POST /msrv/join` (rate limited,
  audited); the panel signs a 90-day leaf with URI SAN
  `bpanel://node/<id>?roles=web,dns,…` (CSR subject/SANs are ignored), returns
  cert + CA. Files go to `/etc/bpanel/node/{node.key,node.crt,ca.crt}` (0600).
  Roles: web, dns, mail, db, backup, monitor.
- **Rotation**: `POST /admin/servers/{id}/rotate` → a rotate token; re-running
  `join` with it issues a new cert for the same node id and revokes the old serial.
- **Revocation**: `msrv_revoked` table. The panel checks the node's serial on
  every handshake (fail closed on DB error). Nodes check the panel's serial
  against `remote_dir/revoked.json` on every handshake; the list is pushed with
  the `revocations` bundle (also auto-enqueued to all active nodes when a node
  is revoked). `POST /admin/servers/{id}/revoke` also invalidates tokens.
- **Agent remote listener** (`internal/agent/msrv_remote.go`): opt-in
  `remote_listen` (e.g. `":8445"`) + `remote_dir`. `tls.Config{MinVersion:
  TLS1.3, ClientAuth: RequireAndVerifyClientCert, ClientCAs: panel CA only}`
  plus identity check (`bpanel://panel`) and revocation. Same JSON line
  protocol and the same `Dispatch` (typed params, unknown-field rejection,
  R2-WB-1 account gate, per-method timeouts). On top a **remote allowlist**:
  ping/info/firewall/revocation for any node; account/vhost/php → `web`, dns →
  `dns`, mail → `mail`, db → `db`, backup run/list/verify → `backup`,
  service status → `monitor`, using roles from the node's own certificate.
  Files, terminal, logs, updates, backup credential export etc. are never
  callable remotely (`msrv_method_not_allowed`).
- **Panel client**: `agentrpc.Client.DialFn` (new optional field) lets the same
  client dial mTLS; `msrv.Manager.CallerFor(nodeID)` returns an `rpc.Caller`
  pinned to the CA and that exact node id. Local socket remains `s.Agent`.
- **Health**: `msrvLoop` pings every active node every minute (latency,
  version, hostname, cert expiry from the verified peer cert) into
  `msrv_nodes`; manual `POST /admin/servers/{id}/health` and `/admin/servers/health`.
- **Jobs / config push**: `jobs.node_id` column (migration 0018). `POST
  /admin/servers/push {bundle, node_ids}` enqueues one `msrv.push` job per node
  (results per node in `GET /admin/servers/{id}/jobs`). Bundles: `firewall`
  (this panel's saved netsec rules + port 8445, applied with the netsec confirm
  timer; the confirm is sent over a fresh mTLS connection, so if the rules cut
  the panel off the node rolls back by itself) and `revocations`. Both replace
  state as a whole, so re-running a job has no double side effects.
- **UI**: Admin → Service configuration → Servers (`Servers.svelte`, `msrv.*` keys EN+TR).
- Free-only: stdlib crypto only, no new dependencies.

## Verified (in-process, real TLS on 127.0.0.1)
mTLS handshake panel client ↔ agent listener, health stored, foreign-CA client
cert rejected, panel trusting a foreign CA rejects node, no client cert
rejected, wrong node id rejected, revoked node serial rejected by panel,
revoked panel serial rejected by agent after revocation push, expired token,
token single use (store + `join` command + HTTP), rotation revokes old serial
and new cert works, remote allowlist (method not allowed, role not held,
unknown method), join with fingerprint pin (wrong pin refused, http refused).

## Not verified / limits
- No real multi-host deployment tested; firewall push to a real node with
  nftables not exercised (netsec apply is covered by netsec's own tests).
- Existing API features (accounts, DNS, …) still use the local agent; routing
  a tenant resource to a node (`node_id` on domains etc.) is a follow-up.
  Server groups, alerting on node down, job re-assignment and templates beyond
  the two bundles are not implemented yet.
- Agent-side revocation of the panel cert depends on the revocation push
  reaching the node; the panel cert is short-lived (90 days) as a backstop.
- The installer does not yet open port 8445 or write `remote_listen`; it is
  configured by hand on nodes.
