-- v0.4 devx: Git Version Control repositories and dynamic DNS hosts.
CREATE TABLE IF NOT EXISTS git_repos (
  id          INTEGER PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  path        TEXT NOT NULL,
  clone_url   TEXT NOT NULL DEFAULT '',
  deploy_path TEXT NOT NULL DEFAULT '',
  last_deploy INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  UNIQUE(user_id, path)
);
CREATE INDEX IF NOT EXISTS git_repos_user ON git_repos(user_id);

-- One DDNS host per subdomain; only the SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS ddns_hosts (
  id          INTEGER PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain_id   INTEGER NOT NULL UNIQUE REFERENCES domains(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  last_ipv4   TEXT NOT NULL DEFAULT '',
  last_ipv6   TEXT NOT NULL DEFAULT '',
  last_update INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ddns_hosts_user ON ddns_hosts(user_id);
