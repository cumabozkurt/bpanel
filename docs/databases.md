# Databases (v0.4 dbx) — spec §13

All features are free / open source (MariaDB GPLv2, PostgreSQL License). Both servers run as
**separate processes**; nothing GPL is linked into the Go binaries (the MariaDB Go driver
`go-sql-driver/mysql` is MPL-2.0 and was already a dependency).

## Remote MySQL (`/databases/remote`, tool `remote_mysql`)
* Per account up to 16 allowed hosts: single IP (v4/v6), IPv4 CIDR /8–/32 (stored by MariaDB as
  `net/netmask`, the only subnet form it accepts) or a DNS hostname. Refused: `%`/`_` wildcards,
  loopback/unspecified/multicast, link-local zones, IPv6 prefixes other than /128, quotes/spaces.
  Validation: `internal/validate/dbhost.go`, run by the API **and** again by the agent.
* The agent action `dbx.remote.sync` receives the *complete desired state* (hosts, users, grants,
  connection limit). For each `<owner>_` user with a local account it creates
  `'user'@'host'` with the **same password hash** (`IDENTIFIED VIA <plugin> USING <hash>`;
  plugins mysql_native_password/ed25519/parsec only), revokes everything and re-grants exactly the
  panel-recorded grants. Remote accounts of `<owner>_` users on hosts no longer allowed are
  dropped. The phpMyAdmin SSO user stays local-only.
* Re-sync happens automatically after DB user create/password change/grant/revoke/wizard (only for
  accounts that use remote hosts or a limit).
* Server-wide switch (admin, `/db-settings`, settings key `dbx_remote_enabled`, default **off**).
  Off ⇒ users cannot add hosts and every remote account is dropped on the next sync / when the
  switch flips. **The switch never opens the firewall**: the admin must add a TCP 3306 allow rule in
  the netsec Firewall page (ideally limited to known sources) and set MariaDB `bind-address`.
  Hostname entries need `skip_name_resolve=OFF` in MariaDB.

## Connection limits
`PUT /admin/accounts/{id}/db-limits {max_user_connections}` (0 = unlimited, max 10000; admin or the
owning reseller). Applied as `MAX_USER_CONNECTIONS` on every MariaDB account of the user
(localhost, 127.0.0.1, ::1 and remote mirrors) and `CONNECTION LIMIT` on the account's PostgreSQL
roles (`pg.limit`).

## Process list (`/databases/processes`, tool `db_processes`)
`dbx.processlist` reads `information_schema.PROCESSLIST` (`USER LIKE '<owner>\_%'`) and
`pg_stat_activity` (`usename LIKE …`, client backends only), re-filters by prefix in Go, query text
truncated to 300 chars. `dbx.kill` checks the owner of the id first, then `KILL QUERY <id>` /
`pg_cancel_backend(pid)` (only cancels the statement; the connection survives).

## PostgreSQL (optional engine, `/postgresql`, tool `postgresql`)
* Installed only with `bpanel-installer --with-postgresql` (Debian/Ubuntu: `postgresql
  postgresql-client`; RHEL family: `postgresql-server postgresql` + `postgresql-setup --initdb`).
  Stage `postgresql` is a no-op otherwise. Not part of any default profile.
* Without PostgreSQL every endpoint answers `pg_not_installed` (422) / `pg_unreachable` (503); the
  UI shows the status and disables actions. No fake success.
* One database + one LOGIN role with the same name `<owner>_<name>` (≤ 63 bytes, `[a-z0-9_]`).
  Role: NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; database OWNER = role,
  `REVOKE ALL ON DATABASE … FROM PUBLIC`, `GRANT CONNECT, TEMPORARY … TO role`.
* Execution: `runuser -u postgres -- psql -X -q -A -t -v ON_ERROR_STOP=1 -d postgres -v k=v …`
  with a **constant** script on stdin. Values are psql variables (`:"ident"`, `:'literal'`, quoted
  by psql) or server-side `format('%I','%L')` via `\gexec`; names are validated on top. Passwords
  never leave the agent in clear text: the agent computes the SCRAM-SHA-256 verifier itself
  (PBKDF2-SHA256, 4096 iterations, RFC 5802/7677) and passes only the verifier. Non-ASCII passwords
  are refused (`password_not_ascii`) because SASLprep is not implemented.
* Sizes: `pg_database_size()` for the owner's databases.
* Backup: when a backup run includes databases, every PostgreSQL database of the account is dumped
  with `pg_dump -Fc --no-owner --no-privileges` into restic as `/pg_<db>.dump` (tag `pgdb,<db>`).
  Restore path `pg:<db>` replays it with `pg_restore --clean --if-exists --single-transaction
  --exit-on-error --no-owner --no-privileges --role=<db>` so the archive runs with the tenant
  role's rights only. Nothing happens on servers without PostgreSQL.

## Tests / verification
* `internal/agent/dbx_test.go`: host validation table (good/bad incl. injection strings), ownership
  refusals before any DB connection, psql argv/stdin contract (constant script, no clear-text
  password, foreign/invalid names never reach psql), SCRAM derivation re-computed, not_installed,
  cross-owner rows filtered, kill of a foreign pid = not_found.
* `internal/api/dbx_test.go`: remote hosts (switch off ⇒ 409, invalid hosts 400, foreign
  list/delete invisible/404, sync params), PostgreSQL (not_installed ⇒ 422 and no agent call,
  name injection 400, foreign delete/password 404), processes/kill validation, admin limits.
* `internal/installer/postgres_test.go`: PostgreSQL absent from all default package lists.
* **Not verified against real servers**: no MariaDB or PostgreSQL server runs in this sandbox (and
  packages may not be installed on the host), so SQL was exercised through fakes only. The SQL text
  follows the MariaDB 10.11 / PostgreSQL 13+ manuals; integration-test on a real host before
  release (especially `IDENTIFIED VIA … USING` hash copy and `\gexec` scripts).
