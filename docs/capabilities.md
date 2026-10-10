# Installed capabilities (profile feature flags)

The installer records which features the installed profile provides, so the API
and UI can hide or refuse what is not installed instead of failing with 502
(R2-SYS-16). It is written on every install and upgrade.

## Where

1. **Panel database settings** (what the API reads with `Store.Get(key, "1")`):

   | key | minimal | web | full |
   |---|---|---|---|
   | `feature_apache` | `0` | `1` | `1` |
   | `feature_dns` | `0` | `1` | `1` |
   | `feature_ftp` | `0` | `1` | `1` |
   | `feature_mail` | `0` | `0` | `1` |
   | `feature_webmail` | `0` | `0` | `1` |
   | `dovecot_syntax` | – | – | `2.3` or `2.4` |
   | `default_php` | detected installed PHP (e.g. `8.3`, `8.4` on Debian 13) | | |
   | `web_mode` | `nginx` | – | – |

   `feature_mail`, `feature_dns` and `feature_apache` already existed; `feature_ftp`,
   `feature_webmail` and `dovecot_syntax` are new. A missing key must be read as
   "installed" (`"1"`) for compatibility with older databases, except that an
   upgrade always writes all of them.

2. **`/etc/bpanel/capabilities.json`** (root:bpanel 0640, readable by the API user):

   ```json
   {
     "version": "1.0.0",
     "profile": "minimal",
     "features": {"apache": false, "backups": true, "cron": true, "dns": false, "ftp": false,
                  "mail": false, "mysql": true, "php": true, "phpmyadmin": true, "sftp": true,
                  "spamfilter": false, "web": true, "webmail": false},
     "default_php": "8.3",
     "dovecot_syntax": ""
   }
   ```

## What the API/agent should do with it (handoff)

- Gate `/user/dns/*`, `/user/ftp*` and the DNS/mail side effects of adding a domain on
  `feature_dns` / `feature_ftp` / `feature_mail`, returning `409 feature_not_installed`
  (as mail already does with `mail_domain_disabled`), and expose the flags in `/api/v1/meta`
  so the UI hides the menu entries.
- Dovecot 2.4 (`dovecot_syntax=2.4`) ignores `userdb_quota_rule=*:storage=<N>M`
  (verified with `doveadm quota get`: no limit); the agent must write
  `userdb_quota_storage_size=<N>M` in `/etc/dovecot/bpanel/passwd` instead. The agent can
  also detect it itself with `dovecot --version`.
