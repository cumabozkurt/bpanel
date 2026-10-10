-- BPANEL schema v5 (v0.4 security foundation)

-- RBAC: staff role on base role admin ('' = super_admin), see internal/rbac.
ALTER TABLE users ADD COLUMN sec_role TEXT NOT NULL DEFAULT '';
-- Step-up authentication: unix time of the last password/TOTP re-auth.
ALTER TABLE sessions ADD COLUMN reauth_at INTEGER NOT NULL DEFAULT 0;
-- Audit: effective role of the actor and the request id.
ALTER TABLE audit_log ADD COLUMN role TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN request_id TEXT NOT NULL DEFAULT '';

CREATE TABLE recovery_codes (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash       TEXT NOT NULL,
  used_at    INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX recovery_codes_user ON recovery_codes(user_id);

CREATE TABLE api_tokens (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  perms        TEXT NOT NULL DEFAULT '',
  ip_allow     TEXT NOT NULL DEFAULT '',
  expires_at   INTEGER NOT NULL DEFAULT 0,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  revoked_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX api_tokens_user ON api_tokens(user_id);

CREATE TABLE tech_grants (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  perms      TEXT NOT NULL DEFAULT '',
  granted_by INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, account_id)
);

CREATE TABLE secrets (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  key_id     TEXT NOT NULL,
  nonce      BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  rotated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE webhooks (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  url        TEXT NOT NULL,
  secret     TEXT NOT NULL DEFAULT '',
  events     TEXT NOT NULL DEFAULT '',
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE webhook_deliveries (
  id          INTEGER PRIMARY KEY,
  webhook_id  INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_id    INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'pending',
  attempts    INTEGER NOT NULL DEFAULT 0,
  http_status INTEGER NOT NULL DEFAULT 0,
  error       TEXT NOT NULL DEFAULT '',
  next_at     INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);
CREATE INDEX webhook_deliveries_hook ON webhook_deliveries(webhook_id);
CREATE INDEX webhook_deliveries_next ON webhook_deliveries(status, next_at);

CREATE TABLE jobs (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'queued',
  owner_id   INTEGER NOT NULL DEFAULT 0,
  payload    TEXT NOT NULL DEFAULT '',
  result     TEXT NOT NULL DEFAULT '',
  error      TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX jobs_status ON jobs(status);
CREATE INDEX jobs_owner ON jobs(owner_id);

CREATE TABLE idempotency_keys (
  user_id    INTEGER NOT NULL,
  key        TEXT NOT NULL,
  req_hash   TEXT NOT NULL,
  status     INTEGER NOT NULL DEFAULT 0,
  body       BLOB,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, key)
);
CREATE INDEX idempotency_keys_created ON idempotency_keys(created_at);

CREATE TABLE events (
  id         INTEGER PRIMARY KEY,
  ts         INTEGER NOT NULL,
  type       TEXT NOT NULL,
  severity   TEXT NOT NULL DEFAULT 'info',
  account_id INTEGER NOT NULL DEFAULT 0,
  data       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX events_ts ON events(ts);
CREATE INDEX events_type ON events(type);
