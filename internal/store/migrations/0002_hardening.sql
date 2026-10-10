-- BPANEL schema v2: security and robustness fixes (audit 2026-10-09)
-- SEC-17: last accepted TOTP time step (replay protection)
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
-- CODE-9: total disk (MB) a reseller may allocate to its accounts (0 = no pool limit)
ALTER TABLE users ADD COLUMN reseller_disk_mb INTEGER NOT NULL DEFAULT 0;

-- CODE-5: completed provisioning / termination steps, compensated in reverse
CREATE TABLE provision_steps (
  user_id INTEGER NOT NULL,
  seq     INTEGER NOT NULL,
  step    TEXT NOT NULL,
  arg     TEXT NOT NULL DEFAULT '',
  done_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, seq)
);

-- CODE-6 / SYS-4: AutoSSL bookkeeping
ALTER TABLE domains ADD COLUMN ssl_attempt_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN ssl_error TEXT NOT NULL DEFAULT '';

-- phpMyAdmin SSO MariaDB users, dropped after their lifetime
CREATE TABLE pma_users (
  db_user    TEXT PRIMARY KEY,
  owner_id   INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

-- SEC-18: per account+IP lockout lookups
CREATE INDEX login_failures_user ON login_failures(username, ip, at);
