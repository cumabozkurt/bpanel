-- v0.4 dnsx: DNS change history (one row per rrset change, revertable) and
-- mlmmj mailing lists. Additive only.

CREATE TABLE IF NOT EXISTS dns_changes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  zone        TEXT NOT NULL,
  name        TEXT NOT NULL,
  type        TEXT NOT NULL,
  action      TEXT NOT NULL,          -- replace | delete | import | reset | revert
  actor       TEXT NOT NULL DEFAULT '',
  before_json TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(before_json)),
  after_json  TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(after_json)),
  revert_of   INTEGER,                -- id of the change this one reverted
  created_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS dns_changes_zone ON dns_changes(user_id, zone, id);

CREATE TABLE IF NOT EXISTS mailing_lists (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain_id  INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  address    TEXT NOT NULL UNIQUE,
  owner      TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS mailing_lists_user ON mailing_lists(user_id);
