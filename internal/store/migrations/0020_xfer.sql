-- v0.4 xfer (spec §10): Transfer Tool runs (fetch / import / export) with
-- their reports. Additive only. Archives themselves live in the agent's
-- xfer directory; remote credentials live in the secret store only while
-- the fetch job runs.

CREATE TABLE IF NOT EXISTS xfer_runs (
  id          INTEGER PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('fetch','import','export')),
  archive     TEXT NOT NULL,
  format      TEXT NOT NULL DEFAULT '',
  username    TEXT NOT NULL DEFAULT '',
  job_id      TEXT NOT NULL UNIQUE,
  actor_id    INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'queued',  -- queued | running | done | failed
  report      TEXT NOT NULL DEFAULT '',        -- JSON report (no secrets)
  created_at  INTEGER NOT NULL,
  finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS xfer_runs_created ON xfer_runs(created_at);
