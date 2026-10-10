-- v0.4 dbx: remote MySQL hosts, per-account DB connection limit, PostgreSQL
-- databases. Additive only. The global "remote MySQL allowed" switch is the
-- settings key dbx_remote_enabled (no schema).

CREATE TABLE IF NOT EXISTS dbx_remote_hosts (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  host       TEXT NOT NULL,          -- as entered, validated (IP, IPv4 CIDR, hostname)
  note       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  UNIQUE (user_id, host)
);

CREATE TABLE IF NOT EXISTS dbx_limits (
  user_id              INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  max_user_connections INTEGER NOT NULL DEFAULT 0 CHECK (max_user_connections BETWEEN 0 AND 10000),
  updated_at           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pg_databases (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL UNIQUE,   -- database and login role share the name
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pg_databases_user ON pg_databases(user_id);
