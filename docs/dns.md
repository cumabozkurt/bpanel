# DNS extras (v0.4 dnsx)

User tool **DNSSEC & Zone Tools** (`/dnsx`) and **Mailing Lists** (`/email/lists`). All free: PowerDNS `pdnsutil` and mlmmj, no paid API.

## DNSSEC
`GET/POST /api/v1/user/dnsx/{domain}/dnssec` -> agent `dns.dnssec` {owner, zone, action status|enable|disable}.
Agent: `mustOwn(zone)`, then `pdnsutil secure-zone Z`, `rectify-zone Z`, `increase-serial Z` (enable) or `disable-dnssec Z` (disable), then `show-zone Z` parsed by `dnsx.ParseShowZone` into DS / DNSKEY. Each command: argv, 60 s timeout. pdnsutil missing -> `status: not_installed` (POST -> 409 `dnssec_not_installed`). The UI shows the DS records to hand to the registrar and warns to remove the DS at the registrar before disabling.

## Zone export / import
- `GET .../export` -> BIND text (`$ORIGIN`, `$TTL`, SOA commented out).
- `POST .../import/preview` {text, mode merge|replace} -> {errors[line,code], notes, changes[add|replace|delete with before/after], findings}.
- `POST .../import/apply` {text, mode, force} -> refuses parse errors (400 `dnsx_import_invalid`) and error-level findings unless `force` (409 `dnsx_check_failed`); applies via the existing `dns.rrset.replace/delete` agent methods, each change recorded in history.
Parser (`internal/dnsx/zonefile.go`), strict: 256 KB, 2000 records, 8 KB lines, `$ORIGIN` must equal the zone, `$TTL`, parentheses, comments, blank owner, `@`, relative/absolute names (must be inside the zone), class IN only, TTL 60-604800 (units 1h/1d accepted). Types A, AAAA, CNAME, MX, TXT, SRV, CAA, NS (sub-delegation only); SOA, apex NS and DNSSEC types are skipped with a note; `$INCLUDE`, `$GENERATE`, other types/classes are errors. Every rdata is validated per type (IPs, u16 fields, host names, TXT quoting/255-char strings, CAA tag). Replace mode never deletes SOA, apex NS or non-editable types.

## Change history + revert
Table `dns_changes` (migration 0016). Every rrset change is recorded with actor, time, before/after JSON: zone editor PUT/DELETE, reset (diff of full zone), import, revert. `GET .../history`; `POST .../history/{id}/revert` restores `before`; refuses with 409 `dnsx_revert_conflict` when the set changed since (UI offers force). Rows are scoped to user_id + zone. History writes are best effort (logged) and never fail a DNS change.

## Consistency checks
`internal/dnsx/check.go`, shown in the import preview and `GET .../check`: errors cname_at_apex, cname_with_other, cname_multiple, cname_loop, mx_to_cname, ns_to_cname, spf_multiple; warnings ttl_low (<300), ttl_high (>1 d), mx_target_missing, below_delegation, delegation_with_other, ttl_mismatch; hints spf_missing, dmarc_missing.

## Mailing lists (mlmmj, MIT)
`GET/POST /user/lists`, `DELETE /user/lists/{id}`, `GET/POST/DELETE /user/lists/{id}/subscribers`. DB table `mailing_lists`; the address may not collide with a mailbox; domain must be the caller's own.
Agent `mlist.apply` (create|delete) / `mlist.subs` (list|add|remove): `mustOwn(mail domain)`, list name `^[a-z0-9][a-z0-9._-]{0,47}$` minus reserved names, path under `/var/spool/mlmmj/<domain>/<list>` (the mlmmj spool layout, control/listaddress, owner, delimiter). The managed transport map `<postfix>/bpanel/bpanel_mlmmj_transport` (`list@domain mlmmj:domain/list`) is regenerated from the spool, `postmap`ed and Postfix reloaded; on postmap/reload failure the previous map is restored and a new list directory removed. Subscribers via `mlmmj-sub/-unsub -L dir -a addr -q -s`, listing via `mlmmj-list -L dir`. Missing mlmmj binaries -> `not_installed` (409 `mlist_not_installed`).
**Installer prerequisite (not done here):** master.cf `mlmmj unix - n n - - pipe flags=ORhu user=mlmmj argv=/usr/bin/mlmmj-receive -F -L /var/spool/mlmmj/$nexthop`, `transport_maps` including the managed map, `recipient_delimiter = +`, and the `mlmmj` package/user.

## Verified / not verified
Verified by unit tests with fakes: parser (25 malformed cases + round trip), checks, diff, show-zone parsing, agent argv/timeouts/ownership/rollback, API ownership (other tenant gets 404 on every endpoint), history/revert/conflict, not_installed paths. **Not verified on a real system:** pdnsutil and mlmmj are not installed in this sandbox; real DNSSEC signing and mail delivery through mlmmj are untested.

## DNS cluster (v0.4 clusterx)

Free, PowerDNS-native primary/secondary replication — no paid clustering
product. BPanel stays the **primary**; secondaries (any RFC-compliant DNS
server: PowerDNS, BIND, Knot, NSD) pull zones by AXFR when notified.

* **Admin → DNS functions → DNS Cluster** (`/admin/dns-cluster`, RBAC `server.read` / `server.write`).
* Secondary IPs are validated (`clusterx.ValidateSecondaryIP`): unicast only;
  loopback, unspecified, multicast, link-local and broadcast are refused;
  private ranges allowed; max 32.
* Apply (agent `cluster.apply`): renders `/etc/powerdns/pdns.d/bpanel-cluster.conf`
  (`primary=yes`, `allow-axfr-ips=…`, `also-notify=…`; PowerDNS ≥ 4.5 names),
  keeps the previous file (and `writeAtomic`'s `.bpanel-bak`), restarts the pdns
  unit, polls the pdns HTTP API until healthy (10 × 1 s) and **restores the
  previous file and restarts again** when it does not come back
  (`cluster_reload_failed`). Then every zone (domains of kind main/addon/alias)
  is switched to kind `Master` and sent a NOTIFY through the local pdns API.
  With no secondaries the managed file is removed. Missing `pdns_server`/`pdnsutil`
  or include-dir → `status: not_installed` with the reason (never a fake success).
* Status (`GET /admin/dns-cluster/status`): SOA of each zone is queried on the
  primary (`clusterx_primary_addr` setting, default `127.0.0.1:53`) and on each
  secondary with `miekg/dns` (UDP, TCP retry on truncation, 3 s timeout, 8
  parallel, ≤ 500 zones). Serials are compared with RFC 1982 arithmetic →
  `in_sync`, `behind`, `ahead`, `missing`, `unreachable`, `unknown`.
* Optional remote PowerDNS API: `POST /admin/dns-cluster/remotes` stores
  name, base URL, the primary IP to pull from, and the API key **in the
  SecretStore** (`clusterx.remote.<id>`). Sync creates every local zone on the
  remote as `kind: Slave, masters: [primary_ip]` (409 = already present).
  The URL goes through the webhook SSRF guard (private/loopback blocked unless
  `webhook_allow_private`), the dialer re-checks the connected IP, redirects
  are not followed.

Verified: IP validation, config rendering, serial arithmetic and state mapping,
real SOA queries against an in-process `miekg/dns` server (answer, REFUSED,
timeout), agent apply / no-op / rollback / removal with fakes for restart and
health, API flow with a fake agent and stubbed SOA queries, SSRF refusal.
Not verified: a real PowerDNS restart and AXFR to a real secondary (no pdns in
the sandbox).
