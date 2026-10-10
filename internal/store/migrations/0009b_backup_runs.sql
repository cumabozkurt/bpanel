-- v0.4 backup part B: scheduled backup runs + retention outcome (additive only).
CREATE TABLE IF NOT EXISTS backup_runs (
  id               INTEGER PRIMARY KEY,
  account_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  username         TEXT NOT NULL,
  trigger          TEXT NOT NULL DEFAULT 'scheduled',
  started_at       INTEGER NOT NULL,
  finished_at      INTEGER NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'running', -- running|ok|failed
  snapshot_ids     TEXT NOT NULL DEFAULT '',
  error            TEXT NOT NULL DEFAULT '',
  retention_status TEXT NOT NULL DEFAULT '',        -- ''|ok|failed|skipped
  retention_error  TEXT NOT NULL DEFAULT '',
  removed          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS backup_runs_acct ON backup_runs(account_id, started_at DESC);
