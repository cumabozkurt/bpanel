-- BPANEL schema v4 (audit round 2, backend)

-- R2-PERF-10: indexes for the per-account lookups and the package/parent joins
CREATE INDEX IF NOT EXISTS mailboxes_user ON mailboxes(user_id);
CREATE INDEX IF NOT EXISTS mailboxes_domain ON mailboxes(domain_id);
CREATE INDEX IF NOT EXISTS forwarders_user ON forwarders(user_id);
CREATE INDEX IF NOT EXISTS forwarders_source ON forwarders(source);
CREATE INDEX IF NOT EXISTS databases_user ON databases(user_id);
CREATE INDEX IF NOT EXISTS db_users_user ON db_users(user_id);
CREATE INDEX IF NOT EXISTS db_grants_user ON db_grants(dbuser_id);
CREATE INDEX IF NOT EXISTS ftp_accounts_user ON ftp_accounts(user_id);
CREATE INDEX IF NOT EXISTS cron_jobs_user ON cron_jobs(user_id);
CREATE INDEX IF NOT EXISTS users_package ON users(package_id);
CREATE INDEX IF NOT EXISTS users_status ON users(status);
CREATE INDEX IF NOT EXISTS domains_parent ON domains(parent_id);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS once_tokens_expires ON once_tokens(expires_at);
CREATE INDEX IF NOT EXISTS login_failures_at ON login_failures(at);

-- G1: limits now use -1 for "unlimited" and 0 for "none". Until now 0 meant
-- unlimited everywhere, so every stored 0 becomes -1 and nothing changes
-- for existing packages, accounts, mailboxes and FTP accounts.
UPDATE packages SET disk_mb=-1 WHERE disk_mb=0;
UPDATE packages SET bandwidth_mb=-1 WHERE bandwidth_mb=0;
UPDATE packages SET max_domains=-1 WHERE max_domains=0;
UPDATE packages SET max_subdomains=-1 WHERE max_subdomains=0;
UPDATE packages SET max_aliases=-1 WHERE max_aliases=0;
UPDATE packages SET max_email=-1 WHERE max_email=0;
UPDATE packages SET max_db=-1 WHERE max_db=0;
UPDATE packages SET max_ftp=-1 WHERE max_ftp=0;
UPDATE packages SET mail_quota_mb=-1 WHERE mail_quota_mb=0;
UPDATE packages SET cpu_percent=-1 WHERE cpu_percent=0;
UPDATE packages SET memory_mb=-1 WHERE memory_mb=0;
UPDATE packages SET max_tasks=-1 WHERE max_tasks=0;
UPDATE users SET max_accounts=-1 WHERE max_accounts=0;
UPDATE users SET reseller_disk_mb=-1 WHERE reseller_disk_mb=0;
UPDATE mailboxes SET quota_mb=-1 WHERE quota_mb=0;
UPDATE ftp_accounts SET quota_mb=-1 WHERE quota_mb=0;

-- R2-PERF-15: optimistic locking (ETag / If-Match) for admin edits
ALTER TABLE packages ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

-- R2-PERF-2: substring search over the audit log without a table scan.
-- The trigram tokenizer keeps the old LIKE '%q%' semantics (case-insensitive
-- substring) for queries of three or more characters.
CREATE VIRTUAL TABLE audit_fts USING fts5(actor, action, target, content='audit_log', content_rowid='id', tokenize='trigram');
INSERT INTO audit_fts(rowid, actor, action, target) SELECT id, actor, action, target FROM audit_log;
CREATE TRIGGER audit_fts_ai AFTER INSERT ON audit_log BEGIN
  INSERT INTO audit_fts(rowid, actor, action, target) VALUES (new.id, new.actor, new.action, new.target);
END;
CREATE TRIGGER audit_fts_ad AFTER DELETE ON audit_log BEGIN
  INSERT INTO audit_fts(audit_fts, rowid, actor, action, target) VALUES ('delete', old.id, old.actor, old.action, old.target);
END;
CREATE TRIGGER audit_fts_au AFTER UPDATE ON audit_log BEGIN
  INSERT INTO audit_fts(audit_fts, rowid, actor, action, target) VALUES ('delete', old.id, old.actor, old.action, old.target);
  INSERT INTO audit_fts(rowid, actor, action, target) VALUES (new.id, new.actor, new.action, new.target);
END;
