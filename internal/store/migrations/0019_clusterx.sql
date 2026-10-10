-- v0.4 clusterx: PowerDNS primary/secondary cluster and signed plugins. Additive only.

CREATE TABLE IF NOT EXISTS dns_cluster_secondaries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ip         TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
);

-- Optional: remote PowerDNS servers driven through their own HTTP API (the
-- API key lives in the SecretStore under clusterx.remote.<id>).
CREATE TABLE IF NOT EXISTS dns_cluster_remotes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  url        TEXT NOT NULL,
  primary_ip TEXT NOT NULL,
  last_sync  INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS plugin_keys (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  pubkey     TEXT NOT NULL UNIQUE,
  key_id     TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS plugins (
  name          TEXT PRIMARY KEY,
  version       TEXT NOT NULL,
  author        TEXT NOT NULL,
  license       TEXT NOT NULL,
  manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
  signer        TEXT NOT NULL DEFAULT '',
  enabled       INTEGER NOT NULL DEFAULT 0,
  webhook_ids   TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(webhook_ids)),
  installed_at  INTEGER NOT NULL DEFAULT 0
);
