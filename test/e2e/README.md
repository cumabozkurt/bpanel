# BPANEL end-to-end suites

Shell suites that drive a **real** BPANEL server through its HTTPS API and check the effect on the
system (Maildir, `dig`, `nft`, `ps`, file owners, IMAP/SMTP/SSH/FTPS logins, …). Results of the
v1.1.0 run: [`docs/evidence/e2e-v1/SUMMARY.md`](../../docs/evidence/e2e-v1/SUMMARY.md).

> Run them only on a **disposable** server or container: they create and delete accounts, change
> the hostname, add IP addresses, touch the firewall and install PHP extensions.

## Container

```sh
sudo podman build -t bpanel-e2e-ubuntu:24.04 -f test/e2e/Containerfile.ubuntu .
sudo podman run -d --name bp-e2e --privileged --hostname panel.e2e.test bpanel-e2e-ubuntu:24.04
sudo podman cp dist/bpanel-1.1.0-linux-amd64.tar.gz bp-e2e:/root/
sudo podman exec -it bp-e2e bash   # then: tar xzf …; BPANEL_ALLOW_UNSIGNED=1 ./install.sh --profile full …
```

Inside, install the client tools the checks use (`jq curl dnsutils swaks mariadb-client
postgresql-client lftp sshpass openssl python3 zip unzip sqlite3 git`) and, for the Shield checks,
ClamAV and YARA.

## Run

```sh
export BP_ADMIN_PASS='…'          # printed once by the installer
export BP_TAG=run1 BP_OUT=$PWD/out # unique suffix for test accounts, output directory
./v11.sh            # v1.1 parity features (needs to run first: creates the webhook receiver + account u$BP_TAG)
./v10.sh            # v0.4 features
./core.sh           # core features (accounts, domains, mail, DNS, SSL, …)
./extra.sh          # Ruby apps, Track DNS NS lookup
./v10.sh setup mail # single sections can be re-run
```

Each check appends a row to `$BP_OUT/results.tsv` (`id, status, area, check, detail`) and every API
call to `$BP_OUT/coverage.tsv`. `tools/matrix.py` turns result files into `docs/feature-matrix.md`.

Helpers: `hook.py` (webhook receiver), `cfmock.py` (local Cloudflare API mock), `wsterm.py`
(terminal WebSocket client), `plugin/` (a signed test plugin and its public key).
AutoSSL checks expect a local Pebble ACME server (`BPANEL_ACME_DIRECTORY` and
`LEGO_CA_CERTIFICATES` in a drop-in of `bpanel-agent.service`).
