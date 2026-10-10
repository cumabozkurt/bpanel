-- v0.4 appx: Application Manager (Node.js / Python apps), app installer and
-- WordPress toolkit. Additive only. Ports are unique per server and taken
-- from the range in appx_settings (port_lo / port_hi, defaults 30000-30999).
CREATE TABLE IF NOT EXISTS appx_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS appx_apps (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain_id   INTEGER REFERENCES domains(id) ON DELETE SET NULL,
  name        TEXT NOT NULL,
  runtime     TEXT NOT NULL,
  version     TEXT NOT NULL,
  root        TEXT NOT NULL,
  startup     TEXT NOT NULL,
  url_path    TEXT NOT NULL DEFAULT '',
  port        INTEGER NOT NULL UNIQUE,
  env         TEXT NOT NULL DEFAULT '{}',
  status      TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS appx_apps_domain ON appx_apps(domain_id);
CREATE TABLE IF NOT EXISTS appx_installs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain_id   INTEGER REFERENCES domains(id) ON DELETE SET NULL,
  app         TEXT NOT NULL,
  version     TEXT NOT NULL,
  path        TEXT NOT NULL,
  url         TEXT NOT NULL DEFAULT '',
  db_name     TEXT NOT NULL DEFAULT '',
  db_user     TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, path)
);
