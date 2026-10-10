-- v1.1 feature parity (additive only): email routing, BoxTrapper, CalDAV /
-- CardDAV logins, dedicated IPs, Cloudflare link.
CREATE TABLE IF NOT EXISTS mail_routing (
  domain     TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mode       TEXT NOT NULL DEFAULT 'auto',   -- auto | local | remote | backup
  effective  TEXT NOT NULL DEFAULT 'local',  -- local | remote | backup
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mail_boxtrapper (
  mailbox_id INTEGER PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
  enabled    INTEGER NOT NULL DEFAULT 0,
  whitelist  TEXT NOT NULL DEFAULT '[]',
  blacklist  TEXT NOT NULL DEFAULT '[]',
  folder     TEXT NOT NULL DEFAULT 'BoxTrapper',
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dav_logins (
  mailbox_id INTEGER PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
  hash       TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS account_ips (
  user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  ip         TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cloudflare_links (
  user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  account    TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0
);
