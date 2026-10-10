-- v0.4 webx: per-domain web extras (directory privacy, hotlink protection,
-- custom error pages, MIME types, IP blocker). Additive only. The config is
-- the JSON of webx.Config (password hashes are bcrypt, never plaintext);
-- rows go away with their domain.
CREATE TABLE IF NOT EXISTS webx_domains (
  domain_id   INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
  config      TEXT NOT NULL DEFAULT '{}',
  version     INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT '',
  updated_at  INTEGER NOT NULL DEFAULT 0
);
