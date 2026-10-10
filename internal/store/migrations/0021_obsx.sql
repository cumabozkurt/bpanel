-- v0.4 obsx: alert rules, notification channels, incidents with history,
-- file-integrity baseline (additive only).
CREATE TABLE IF NOT EXISTS obsx_rules (
  id           TEXT PRIMARY KEY,
  enabled      INTEGER NOT NULL DEFAULT 1,
  severity     TEXT NOT NULL DEFAULT 'warning',
  threshold    REAL NOT NULL DEFAULT 0,
  cooldown_sec INTEGER NOT NULL DEFAULT 3600
);

CREATE TABLE IF NOT EXISTS obsx_channels (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL,
  kind         TEXT NOT NULL,              -- email | telegram | slack | discord
  target       TEXT NOT NULL DEFAULT '',   -- email address(es) / telegram chat id (never a secret)
  min_severity TEXT NOT NULL DEFAULT 'warning',
  enabled      INTEGER NOT NULL DEFAULT 1,
  last_status  TEXT NOT NULL DEFAULT '',
  last_error   TEXT NOT NULL DEFAULT '',
  last_at      INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS obsx_incidents (
  id               INTEGER PRIMARY KEY,
  dedup_key        TEXT NOT NULL,
  rule             TEXT NOT NULL,
  severity         TEXT NOT NULL,
  title            TEXT NOT NULL,
  detail           TEXT NOT NULL DEFAULT '',
  account_id       INTEGER NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'open', -- open | acknowledged | resolved
  assignee_id      INTEGER NOT NULL DEFAULT 0,
  count            INTEGER NOT NULL DEFAULT 1,
  first_at         INTEGER NOT NULL,
  last_at          INTEGER NOT NULL,
  last_notified_at INTEGER NOT NULL DEFAULT 0,
  resolved_at      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS obsx_incidents_key ON obsx_incidents(dedup_key, status);
CREATE INDEX IF NOT EXISTS obsx_incidents_status ON obsx_incidents(status, last_at);

CREATE TABLE IF NOT EXISTS obsx_incident_history (
  id          INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES obsx_incidents(id) ON DELETE CASCADE,
  at          INTEGER NOT NULL,
  actor_id    INTEGER NOT NULL DEFAULT 0,
  actor       TEXT NOT NULL DEFAULT '',
  action      TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS obsx_incident_history_inc ON obsx_incident_history(incident_id, at);

CREATE TABLE IF NOT EXISTS obsx_fim_baseline (
  path       TEXT PRIMARY KEY,
  mode       TEXT NOT NULL,
  sha256     TEXT NOT NULL DEFAULT '',
  size       INTEGER NOT NULL DEFAULT 0,
  mtime      INTEGER NOT NULL DEFAULT 0,
  uid        INTEGER NOT NULL DEFAULT 0,
  gid        INTEGER NOT NULL DEFAULT 0,
  perm       INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
