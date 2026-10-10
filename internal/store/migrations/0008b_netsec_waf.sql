-- v0.4 network security part B (API + WAF). Additive only.
-- Firewall versions: confirm token (sha256) + deadline of a pending apply.
ALTER TABLE fw_changes ADD COLUMN token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE fw_changes ADD COLUMN deadline INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fw_changes ADD COLUMN reason TEXT NOT NULL DEFAULT '';
ALTER TABLE fw_changes ADD COLUMN rollback_of INTEGER NOT NULL DEFAULT 0;

-- Per-domain WAF state (waf_rules from 0008 only allows audit|block, so the
-- per-domain mode incl. 'off' lives here; every applied version is kept in
-- waf_changes).
CREATE TABLE IF NOT EXISTS waf_domains (
  domain      TEXT PRIMARY KEY,
  mode        TEXT NOT NULL DEFAULT 'audit' CHECK (mode IN ('audit','block','off')),
  exclusions  TEXT NOT NULL DEFAULT '[]',          -- JSON array of numeric rule IDs
  version     INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT '',            -- applied | not_installed | failed
  reason      TEXT NOT NULL DEFAULT '',
  updated_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS waf_changes (
  id          INTEGER PRIMARY KEY,
  domain      TEXT NOT NULL,
  version     INTEGER NOT NULL,
  mode        TEXT NOT NULL,
  exclusions  TEXT NOT NULL DEFAULT '[]',
  status      TEXT NOT NULL DEFAULT '',
  applied_by  INTEGER,
  created_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS waf_changes_domain ON waf_changes(domain, version);
