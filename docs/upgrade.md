# Upgrading

## v0.4.0 → v1.0.0

v1.0.0 is a release-audit version of v0.4.0: **no new database migration, no new package, no new
service**. The upgrade replaces the binaries and units, re-applies the configuration of the release
and runs the self-test. Websites, mail and data stay online.

```sh
# from the unpacked v1.0.0 archive (unsigned, check the published SHA-256 first):
sudo BPANEL_ALLOW_UNSIGNED=1 ./install.sh upgrade
# or, after copying the new bpanel-installer to the server:
sudo bpanel-installer upgrade
```

The steps are the same as below and are recorded as `upgrade-1.0.0:<step>`; the pre-upgrade backup
goes to `/var/backups/bpanel/upgrade-0.4.0-to-1.0.0-<UTC time>/`. Behaviour changes to know about:

- The `--node` join hint now names port **2083** (where `/msrv/join` is served); `8443` was wrong.
- Nothing else visible changes; see `CHANGELOG.md` (v1.0.0) for the fixed tests and tooling.

**Rollback to v0.4.0:** the database schema is identical, so stop `bpanel-api` and `bpanel-agent`, put
the v0.4.0 binaries back into `/usr/local/lib/bpanel` and start the services again (`bpanel selftest`).

## v0.3 → v0.4

```sh
curl -fsSL https://get.bozkurtpanel.com | sudo bash -s -- upgrade
# or, with the new installer binary on the server:
sudo bpanel-installer upgrade
```

## What happens, in order

Each step is recorded as `upgrade-0.4.0:<step>` in `/var/lib/bpanel/install-state.json`, so an interrupted upgrade
resumes and a repeated one changes nothing (`--force` re-applies every step).

1. **preflight** – root, supported OS.
2. **backup** – before anything changes: a consistent `VACUUM INTO` copy of `/var/lib/bpanel/db/bpanel.db` (safe while
   the API runs) and `etc-bpanel.tar.gz` of `/etc/bpanel`, in
   `/var/backups/bpanel/upgrade-<from>-to-<to>-<UTC time>/` (directory 0700, files 0600; contains secrets – keep it
   root-only). Every run creates a new directory; nothing is overwritten.
3. **packages** – only *missing* packages of the profile plus the v0.4 ones (chrony, traceroute, git; mlmmj on `full`,
   optional ones as warnings). Installed packages are not upgraded.
4. **restic**, **system**, **configs** (now including the v0.4 step: directories, `bpanel-app@.service`, mlmmj
   transport, chrony), **panel** (new binaries + units).
5. **Database migrations** run when the new API starts (`store.Open`): every migration not yet in
   `schema_migrations` is applied in name order – for v0.3 that is `0005_security` … `0021_obsx` (including the `b`
   files such as `0008b_netsec_waf`, `0009b_backup_runs`). Each runs in its own transaction; already applied ones are
   checksum-verified and skipped. All v0.4 migrations are additive (CREATE TABLE/INDEX, ADD COLUMN).
6. **selftest** + summary.

Tested: `internal/store/upgrade_v04_test.go` builds a v0.3 database (0001–0004 with v0.3 bookkeeping and data), opens it
with the v0.4 store and checks every migration is applied and the data is kept; a fresh database and a second open
(idempotent re-run) are tested too. `internal/installer/v04_test.go` tests the backup (DB copy readable, tar contents).

## Rollback

v0.4 migrations are additive, so the v0.3 binaries keep working on a v0.4 database **except** that the v0.3 store
refuses a database with unknown migrations (`ErrSchemaTooNew`). Roll back like this:

```sh
B=/var/backups/bpanel/upgrade-0.3.0-to-0.4.0-<time>
systemctl stop bpanel-api bpanel-agent
cp /var/lib/bpanel/db/bpanel.db /var/lib/bpanel/db/bpanel.db.v04       # keep the v0.4 state
install -o bpanel -g bpanel -m 0600 $B/bpanel.db /var/lib/bpanel/db/bpanel.db
rm -f /var/lib/bpanel/db/bpanel.db-wal /var/lib/bpanel/db/bpanel.db-shm
tar -C /etc -xzf $B/etc-bpanel.tar.gz                                    # restores /etc/bpanel
# reinstall the v0.3 binaries (dist/BPANEL-v0.3.zip or the v0.3 release) into /usr/local/lib/bpanel
systemctl start bpanel-agent bpanel-api && bpanel selftest
```

Changes made in the panel after the upgrade are lost by a rollback (they live in the v0.4 database). Packages added
by the upgrade (chrony, mlmmj, …) are harmless to v0.3 and can stay. The Postfix `transport_maps`/mlmmj entries may
stay as well; remove them with `postconf -X transport_maps; postconf -MX mlmmj/unix` if you want a clean v0.3 config.
