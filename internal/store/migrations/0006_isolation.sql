-- v0.4 per-account resource isolation (bpanel-u-<user>.slice).
-- Hosting accounts are rows of `users`; zero in a limit column = unlimited.
CREATE TABLE limit_profiles (
  id             INTEGER PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  cpu_percent    INTEGER NOT NULL DEFAULT 0 CHECK (cpu_percent >= 0),
  cpu_weight     INTEGER NOT NULL DEFAULT 0 CHECK (cpu_weight >= 0),
  mem_max_mb     INTEGER NOT NULL DEFAULT 0 CHECK (mem_max_mb >= 0),
  mem_high_mb    INTEGER NOT NULL DEFAULT 0 CHECK (mem_high_mb >= 0),
  io_read_bps    INTEGER NOT NULL DEFAULT 0 CHECK (io_read_bps >= 0),
  io_write_bps   INTEGER NOT NULL DEFAULT 0 CHECK (io_write_bps >= 0),
  io_read_iops   INTEGER NOT NULL DEFAULT 0 CHECK (io_read_iops >= 0),
  io_write_iops  INTEGER NOT NULL DEFAULT 0 CHECK (io_write_iops >= 0),
  tasks_max      INTEGER NOT NULL DEFAULT 0 CHECK (tasks_max >= 0),
  inode_limit    INTEGER NOT NULL DEFAULT 0 CHECK (inode_limit >= 0),
  disk_mb        INTEGER NOT NULL DEFAULT 0 CHECK (disk_mb >= 0),
  entry_procs    INTEGER NOT NULL DEFAULT 0 CHECK (entry_procs >= 0),
  created_at     INTEGER NOT NULL DEFAULT 0,
  updated_at     INTEGER NOT NULL DEFAULT 0
);

ALTER TABLE users ADD COLUMN limit_profile_id INTEGER REFERENCES limit_profiles(id) ON DELETE SET NULL;
-- Per-account overrides of single profile fields, JSON object keyed like
-- isolation.Profile ({"mem_max_mb":1024}).
ALTER TABLE users ADD COLUMN limit_overrides TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(limit_overrides));

-- Usage samples per account and time bucket (sampler, 1-minute buckets).
-- events: JSON object of counter deltas ({"oom_kill":1,"mem_high":3}).
CREATE TABLE usage_samples (
  account_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  bucket_ts   INTEGER NOT NULL,
  cpu_usec    INTEGER NOT NULL DEFAULT 0,
  mem_bytes   INTEGER NOT NULL DEFAULT 0,
  io_r        INTEGER NOT NULL DEFAULT 0,
  io_w        INTEGER NOT NULL DEFAULT 0,
  pids        INTEGER NOT NULL DEFAULT 0,
  events      TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (account_id, bucket_ts)
);
CREATE INDEX usage_samples_bucket ON usage_samples(bucket_ts);
