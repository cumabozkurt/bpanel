-- BPANEL schema v1
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE packages (
  id             INTEGER PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  owner_id       INTEGER,
  disk_mb        INTEGER NOT NULL DEFAULT 0,
  bandwidth_mb   INTEGER NOT NULL DEFAULT 0,
  max_domains    INTEGER NOT NULL DEFAULT 0,
  max_subdomains INTEGER NOT NULL DEFAULT 0,
  max_aliases    INTEGER NOT NULL DEFAULT 0,
  max_email      INTEGER NOT NULL DEFAULT 0,
  max_db         INTEGER NOT NULL DEFAULT 0,
  max_ftp        INTEGER NOT NULL DEFAULT 0,
  mail_quota_mb  INTEGER NOT NULL DEFAULT 1024,
  cpu_percent    INTEGER NOT NULL DEFAULT 100,
  memory_mb      INTEGER NOT NULL DEFAULT 1024,
  max_tasks      INTEGER NOT NULL DEFAULT 200,
  php_version    TEXT NOT NULL DEFAULT '',
  created_at     INTEGER NOT NULL
);

CREATE TABLE users (
  id             INTEGER PRIMARY KEY,
  username       TEXT NOT NULL UNIQUE,
  role           TEXT NOT NULL CHECK (role IN ('admin','reseller','user')),
  owner_id       INTEGER REFERENCES users(id),
  package_id     INTEGER REFERENCES packages(id),
  email          TEXT NOT NULL DEFAULT '',
  password_hash  TEXT NOT NULL,
  totp_secret    TEXT NOT NULL DEFAULT '',
  totp_enabled   INTEGER NOT NULL DEFAULT 0,
  lang           TEXT NOT NULL DEFAULT '',
  theme          TEXT NOT NULL DEFAULT 'light',
  status         TEXT NOT NULL DEFAULT 'active',
  suspend_reason TEXT NOT NULL DEFAULT '',
  system_user    INTEGER NOT NULL DEFAULT 0,
  uid            INTEGER NOT NULL DEFAULT 0,
  home           TEXT NOT NULL DEFAULT '',
  primary_domain TEXT NOT NULL DEFAULT '',
  php_version    TEXT NOT NULL DEFAULT '',
  web_mode       TEXT NOT NULL DEFAULT 'nginx-apache',
  max_accounts   INTEGER NOT NULL DEFAULT 0,
  last_login_at  INTEGER NOT NULL DEFAULT 0,
  last_login_ip  TEXT NOT NULL DEFAULT '',
  created_at     INTEGER NOT NULL
);
CREATE INDEX users_owner ON users(owner_id);

CREATE TABLE domains (
  id          INTEGER PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL UNIQUE,
  kind        TEXT NOT NULL CHECK (kind IN ('main','addon','sub','alias')),
  parent_id   INTEGER REFERENCES domains(id) ON DELETE CASCADE,
  docroot     TEXT NOT NULL DEFAULT 'public_html',
  php_version TEXT NOT NULL DEFAULT '',
  redirect    TEXT NOT NULL DEFAULT '',
  ssl_status  TEXT NOT NULL DEFAULT 'none',
  ssl_expires TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE INDEX domains_user ON domains(user_id);

CREATE TABLE databases (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE db_users (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE db_grants (
  db_id      INTEGER NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  dbuser_id  INTEGER NOT NULL REFERENCES db_users(id) ON DELETE CASCADE,
  privileges TEXT NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (db_id, dbuser_id)
);

CREATE TABLE mailboxes (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain_id  INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  email      TEXT NOT NULL UNIQUE,
  quota_mb   INTEGER NOT NULL DEFAULT 1024,
  created_at INTEGER NOT NULL
);

CREATE TABLE forwarders (
  id          INTEGER PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source      TEXT NOT NULL,
  destination TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  UNIQUE (source, destination)
);

CREATE TABLE ftp_accounts (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  login      TEXT NOT NULL UNIQUE,
  dir        TEXT NOT NULL DEFAULT '',
  quota_mb   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE cron_jobs (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  minute     TEXT NOT NULL,
  hour       TEXT NOT NULL,
  dom        TEXT NOT NULL,
  month      TEXT NOT NULL,
  dow        TEXT NOT NULL,
  command    TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  id_hash         TEXT PRIMARY KEY,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  impersonator_id INTEGER NOT NULL DEFAULT 0,
  realm           TEXT NOT NULL,
  csrf            TEXT NOT NULL,
  ip              TEXT NOT NULL,
  user_agent      TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  last_seen       INTEGER NOT NULL
);

CREATE TABLE once_tokens (
  hash       TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  realm      TEXT NOT NULL,
  impersonator_id INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
  id       INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  actor_id INTEGER NOT NULL DEFAULT 0,
  actor    TEXT NOT NULL DEFAULT '',
  ip       TEXT NOT NULL DEFAULT '',
  realm    TEXT NOT NULL DEFAULT '',
  action   TEXT NOT NULL,
  target   TEXT NOT NULL DEFAULT '',
  detail   TEXT NOT NULL DEFAULT '',
  ok       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX audit_at ON audit_log(at);

CREATE TABLE pma_tokens (
  hash       TEXT PRIMARY KEY,
  db_user    TEXT NOT NULL,
  password   TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE login_failures (
  ip       TEXT NOT NULL,
  username TEXT NOT NULL,
  at       INTEGER NOT NULL
);
CREATE INDEX login_failures_ip ON login_failures(ip, at);
