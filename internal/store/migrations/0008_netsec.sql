-- v0.4 network security (part A firewall, part B WAF placeholder). Additive only.
CREATE TABLE IF NOT EXISTS fw_rules (
  id           INTEGER PRIMARY KEY,
  action       TEXT NOT NULL CHECK (action IN ('allow','deny','ratelimit')),
  family       TEXT NOT NULL DEFAULT 'inet' CHECK (family IN ('ip','ip6','inet')),
  cidr         TEXT NOT NULL DEFAULT '',
  proto        TEXT NOT NULL DEFAULT '' CHECK (proto IN ('','tcp','udp')),
  ports        TEXT NOT NULL DEFAULT '',          -- comma separated
  rate_per_min INTEGER NOT NULL DEFAULT 0 CHECK (rate_per_min >= 0),
  comment      TEXT NOT NULL DEFAULT '',
  source       TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','auto')),
  expires_at   INTEGER NOT NULL DEFAULT 0,        -- unix seconds, 0 = permanent
  created_by   INTEGER,
  created_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS fw_rules_expires ON fw_rules(expires_at);

CREATE TABLE IF NOT EXISTS fw_blocks (
  id          INTEGER PRIMARY KEY,
  ip          TEXT NOT NULL,                       -- address or CIDR, normalised
  reason      TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','auto','fail2ban','crowdsec')),
  expires_at  INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS fw_blocks_ip ON fw_blocks(ip);
CREATE INDEX IF NOT EXISTS fw_blocks_expires ON fw_blocks(expires_at);

CREATE TABLE IF NOT EXISTS fw_changes (
  version       INTEGER PRIMARY KEY,
  ruleset_text  TEXT NOT NULL,                     -- rendered nft script
  ruleset_json  TEXT NOT NULL DEFAULT '',          -- netsec.Ruleset as JSON
  applied_by    INTEGER,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','rolled_back','unsupported')),
  created_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS waf_rules (
  id         INTEGER PRIMARY KEY,
  rule_text  TEXT NOT NULL,
  mode       TEXT NOT NULL DEFAULT 'audit' CHECK (mode IN ('audit','block')),
  version    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT 0
);
