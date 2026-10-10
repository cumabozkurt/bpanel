-- v0.4 msrv (spec §16): remote nodes over mTLS. Additive only.
CREATE TABLE IF NOT EXISTS msrv_nodes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL UNIQUE,
  address      TEXT NOT NULL DEFAULT '',      -- host:port of the agent remote listener
  roles        TEXT NOT NULL DEFAULT '',      -- comma separated: web,dns,mail,db,backup,monitor
  status       TEXT NOT NULL DEFAULT 'pending', -- pending | active | revoked
  cert_serial  TEXT NOT NULL DEFAULT '',
  cert_not_after INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  enrolled_at  INTEGER NOT NULL DEFAULT 0,
  last_seen    INTEGER NOT NULL DEFAULT 0,
  last_check   INTEGER NOT NULL DEFAULT 0,
  latency_ms   INTEGER NOT NULL DEFAULT -1,
  version      TEXT NOT NULL DEFAULT '',
  health       TEXT NOT NULL DEFAULT 'unknown', -- unknown | ok | down
  health_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS msrv_join_tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id     INTEGER NOT NULL,
  token_hash  TEXT NOT NULL UNIQUE,            -- sha256 hex, the token itself is never stored
  purpose     TEXT NOT NULL DEFAULT 'join',    -- join | rotate
  created_by  INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS msrv_join_tokens_node ON msrv_join_tokens(node_id);
CREATE TABLE IF NOT EXISTS msrv_revoked (
  serial     TEXT PRIMARY KEY,
  node_id    INTEGER NOT NULL DEFAULT 0,
  reason     TEXT NOT NULL DEFAULT '',
  revoked_at INTEGER NOT NULL
);
ALTER TABLE jobs ADD COLUMN node_id INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS jobs_node ON jobs(node_id);
