-- v0.4 mailx: user mail tools (autoresponders, filters, spam filters). Additive only.
CREATE TABLE IF NOT EXISTS mail_autoresponders (
  mailbox_id    INTEGER PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject       TEXT NOT NULL,
  body          TEXT NOT NULL,
  start_date    TEXT NOT NULL DEFAULT '',
  end_date      TEXT NOT NULL DEFAULT '',
  interval_days INTEGER NOT NULL DEFAULT 1,
  from_addr     TEXT NOT NULL DEFAULT '',
  enabled       INTEGER NOT NULL DEFAULT 1,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_autoresponders_user ON mail_autoresponders(user_id);
CREATE TABLE IF NOT EXISTS mail_filters (
  id          INTEGER PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mailbox_id  INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  field       TEXT NOT NULL,
  header      TEXT NOT NULL DEFAULT '',
  op          TEXT NOT NULL,
  value       TEXT NOT NULL,
  action      TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_filters_box ON mail_filters(mailbox_id, id);
-- last apply result of a mailbox's managed Sieve script: active|inactive|not_installed
CREATE TABLE IF NOT EXISTS mail_sieve_status (
  mailbox_id  INTEGER PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
  status      TEXT NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mail_spam (
  user_id        INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  enabled        INTEGER NOT NULL DEFAULT 1,
  required_score REAL NOT NULL DEFAULT 6,
  allow_list     TEXT NOT NULL DEFAULT '',
  deny_list      TEXT NOT NULL DEFAULT '',
  status         TEXT NOT NULL DEFAULT '',
  reason         TEXT NOT NULL DEFAULT '',
  updated_at     INTEGER NOT NULL
);
