-- v0.4 usagex: per-domain daily bandwidth, log cursors, per-account PHP ini
-- overrides, brute-force allowlist (additive only).
CREATE TABLE IF NOT EXISTS bw_daily (
  domain TEXT NOT NULL,
  day    TEXT NOT NULL,            -- YYYY-MM-DD (UTC)
  bytes  INTEGER NOT NULL DEFAULT 0,
  hits   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (domain, day)
);
CREATE INDEX IF NOT EXISTS bw_daily_day ON bw_daily(day);
CREATE TABLE IF NOT EXISTS bw_cursors (
  domain     TEXT PRIMARY KEY,
  inode      INTEGER NOT NULL DEFAULT 0,
  offset     INTEGER NOT NULL DEFAULT 0,
  status     TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS php_ini_settings (
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  version    TEXT NOT NULL,
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, version, key)
);
CREATE TABLE IF NOT EXISTS bf_allowlist (
  id         INTEGER PRIMARY KEY,
  ip         TEXT NOT NULL UNIQUE,
  note       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
);
-- WAF mode locked by an admin/reseller (the account owner cannot change it).
CREATE TABLE IF NOT EXISTS waf_locks (
  domain     TEXT PRIMARY KEY,
  locked     INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);
