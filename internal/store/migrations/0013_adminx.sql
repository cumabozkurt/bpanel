-- v0.4 adminx: Modify Account overrides, reseller limits/ACL (Edit Reseller).
-- Additive only. Server update preferences live in the settings table
-- (update_policy, update_auto_reboot) and need no schema.

-- Per-account overrides set by Modify Account. NULL = use the package value.
CREATE TABLE IF NOT EXISTS account_overrides (
  user_id           INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  shell_access      INTEGER NOT NULL DEFAULT 0 CHECK (shell_access IN (0,1)),
  max_addon_domains INTEGER,
  max_subdomains    INTEGER,
  updated_at        INTEGER NOT NULL DEFAULT 0
);

-- Reseller limits beyond users.max_accounts / users.reseller_disk_mb.
-- bandwidth_mb: -1 = no pool limit. allowed_packages / acl: JSON arrays;
-- [] = no restriction (all own packages / the full reseller role).
CREATE TABLE IF NOT EXISTS reseller_limits (
  user_id          INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  bandwidth_mb     INTEGER NOT NULL DEFAULT -1,
  allowed_packages TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_packages)),
  acl              TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(acl)),
  updated_at       INTEGER NOT NULL DEFAULT 0
);
