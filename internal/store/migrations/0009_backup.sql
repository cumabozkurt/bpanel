-- v0.4 backup module: restore verification results (additive only).
CREATE TABLE IF NOT EXISTS backup_verifications (
  id             INTEGER PRIMARY KEY,
  account_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  username       TEXT NOT NULL,
  snapshot_id    TEXT NOT NULL DEFAULT '',
  started_at     INTEGER NOT NULL,
  finished_at    INTEGER NOT NULL DEFAULT 0,
  files_checked  INTEGER NOT NULL DEFAULT 0,
  mismatches     INTEGER NOT NULL DEFAULT 0,
  check_ok       INTEGER NOT NULL DEFAULT 0,
  status         TEXT NOT NULL DEFAULT 'running', -- running|ok|failed|no_snapshot|no_manifest|error
  error          TEXT NOT NULL DEFAULT '',
  trigger        TEXT NOT NULL DEFAULT 'manual'   -- manual|scheduled
);
CREATE INDEX IF NOT EXISTS backup_verifications_acct ON backup_verifications(account_id, started_at DESC);
