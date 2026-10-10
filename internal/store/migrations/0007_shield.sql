-- v0.4 BPanel Shield: detections pulled from the agent journal, an index of
-- the agent's encrypted quarantine, and per-class policies (account_id NULL =
-- server-wide default; an account row overrides it for that class).
CREATE TABLE shield_detections (
  id                   INTEGER PRIMARY KEY,
  event_uid            TEXT NOT NULL UNIQUE,
  seq                  INTEGER NOT NULL DEFAULT 0,
  ts                   INTEGER NOT NULL,
  account_id           INTEGER REFERENCES users(id) ON DELETE SET NULL,
  account              TEXT NOT NULL DEFAULT '',
  kind                 TEXT NOT NULL DEFAULT '',
  source               TEXT NOT NULL DEFAULT '',
  path                 TEXT NOT NULL DEFAULT '',
  sha256               TEXT NOT NULL DEFAULT '',
  outcome              TEXT NOT NULL DEFAULT '',
  action               TEXT NOT NULL DEFAULT '',
  reason               TEXT NOT NULL DEFAULT '',
  engine               TEXT NOT NULL DEFAULT '',
  signature            TEXT NOT NULL DEFAULT '',
  severity             TEXT NOT NULL DEFAULT '',
  detections_json      TEXT NOT NULL DEFAULT '[]',
  quarantine_id        TEXT NOT NULL DEFAULT '',
  restore_requested_at INTEGER
);
CREATE INDEX shield_detections_account ON shield_detections(account_id, ts);
CREATE INDEX shield_detections_ts ON shield_detections(ts);

CREATE TABLE shield_quarantine_index (
  id              TEXT PRIMARY KEY,
  account_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  account         TEXT NOT NULL DEFAULT '',
  orig_path       TEXT NOT NULL DEFAULT '',
  sha256          TEXT NOT NULL DEFAULT '',
  size            INTEGER NOT NULL DEFAULT 0,
  ts              INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'quarantined' CHECK (status IN ('quarantined','restored','deleted','false_positive')),
  detections_json TEXT NOT NULL DEFAULT '[]',
  updated_at      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX shield_quarantine_account ON shield_quarantine_index(account_id, status);

CREATE TABLE shield_policies (
  id             INTEGER PRIMARY KEY,
  account_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  file_class     TEXT NOT NULL CHECK (file_class IN ('script','executable','archive','other')),
  on_unavailable TEXT NOT NULL DEFAULT '' CHECK (on_unavailable IN ('','allow_with_warning','block','hold')),
  on_suspicious  TEXT NOT NULL DEFAULT '' CHECK (on_suspicious IN ('','allow_with_warning','block','quarantine','hold')),
  updated_at     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX shield_policies_class ON shield_policies(IFNULL(account_id, 0), file_class);

-- poller cursor (last agent journal sequence stored)
CREATE TABLE shield_cursor (
  id       INTEGER PRIMARY KEY CHECK (id = 1),
  last_seq INTEGER NOT NULL DEFAULT 0
);
INSERT INTO shield_cursor(id, last_seq) VALUES (1, 0);
