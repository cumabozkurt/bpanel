# Account isolation (v0.4)

Every hosting account gets its own resource box (cgroup v2 slice), its own
PHP-FPM service, a filesystem cage, hidden processes, caged cron jobs, and an
SSH jail. All privileged steps run in the root agent through typed, allowlisted
actions with argv-only execution.

## cgroups v2 slices and limits
- Hierarchy: `bpanel.slice/bpanel-u.slice/bpanel-u-<user>.slice` (`isolation.SliceName`, `CgroupDir`).
- `isolation.RenderSlice` maps a limit profile to systemd directives: `CPUQuota`, `CPUWeight`,
  `MemoryHigh`, `MemoryMax` (+ `MemorySwapMax=0`), `IO{Read,Write}{BandwidthMax,IOPSMax}` on the
  account's block device, `TasksMax`.
- Agent: `isolation.apply` writes the unit and runs `systemctl daemon-reload`; when systemd is not
  PID 1 (or `no_systemd`) it returns `applied_files_only` with a reason - never a fake "applied".
  `isolation.status` probes cgroup v2 + controllers; `isolation.stats` reads cpu/memory/io/pids counters.
- API: limit profiles CRUD, per-account overrides (resellers cannot exceed their own allowance),
  usage history (5-min buckets, 30-day retention) and `iso.limit_hit` events from the sampler.

## Per-account PHP-FPM
`isolation.RenderFPMService` renders `bpanel-php-<user>-<ver>.service` with `Slice=` the account
slice, `ProtectSystem=strict`, `ProtectHome=tmpfs` + `BindPaths=/home/<user>`, `PrivateTmp`,
`PrivateDevices`, `ProtectProc=invisible`. `NoNewPrivileges=no` is deliberate: PHP `mail()` needs
setgid `postdrop`.

## Filesystem cage (bwrap / unshare fallback)
- SSH sessions in `cage` mode run through `/usr/local/lib/bpanel/bpanel-cage-shell`
  (`isolation.RenderCageShell`): bubblewrap with read-only `/usr` and `/etc`, a tmpfs `/home` with
  only the account's home bound in, private `/tmp`, PID/IPC/UTS namespaces. Without bwrap it fails
  closed (exit 126) instead of handing out an unjailed shell.
- The kernel test falls back to `unshare -m` + tmpfs over `/home` when bwrap is missing.

## hidepid
- Installer step `system:hidepid`: creates group `bpanel-proc`, adds existing service users
  (`bpanel`, `bpanel-apps`, `polkitd`, common monitoring daemons) to it, writes
  `proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2,gid=<gid> 0 0` to `/etc/fstab`
  idempotently (`isolation.RenderFstab`: any other `/proc` line is kept commented as
  `#bpanel-replaced:`; a re-run is a no-op), keeps the original once as `/etc/fstab.bpanel-orig`,
  validates the full file structurally and our line with `findmnt --verify`, restores the previous
  file on failure, then `mount -o remount,hidepid=2,gid=<gid> /proc` (failure = warning, applies at boot).
- Agent: `isolation.hidepid.status` -> `active | configured_reboot_pending | not_configured | unsupported`
  from `/proc/self/mountinfo` and `/etc/fstab`.
- FPM units additionally use `ProtectProc=invisible` (systemd's per-service equivalent).

## Cron cage
- The user's command is never on a root command line. It is stored as
  `/var/lib/bpanel/cron/<user>/<id>.sh` (`RenderCronScript`) and `/etc/cron.d/bpanel-<user>`
  (`RenderCronD`) contains only validated tokens:
  - systemd: `systemd-run --quiet --collect --wait --slice=bpanel-u-<user>.slice --unit=bpanel-cron-<user>-<id> --uid=<uid> --gid=<gid> --property=NoNewPrivileges=yes --property=PrivateTmp=yes --working-directory=/home/<user> -- /bin/sh <script>`
  - no systemd: `bpanel-agent cage-exec --cgroup <slice dir> --uid --gid --chdir /home/<user> -- /bin/sh <script>`
    (`isolation.CageExec`: joins the cgroup, setgroups/setgid/setuid, `PR_SET_NO_NEW_PRIVS`, exec).
- Validation: schedule = 5 cron fields of `[0-9A-Za-z*/,-]` or an `@macro`; command = one line
  (no NUL/CR/LF, so it cannot add a cron.d entry); uid/gid >= 1000; tokens without shell
  metacharacters or `%`. The only interpreter of user text is `/bin/sh` running as that user.

## SSH jail
`isolation.ssh.apply` renders `/etc/ssh/sshd_config.d/60-bpanel-jail.conf` with one
`Match User <account>` block each: `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`,
`X11Forwarding no`, `AllowAgentForwarding no`, `PermitTunnel no`, and either
`ForceCommand bpanel-cage-shell` (cage) or `ChrootDirectory /var/lib/bpanel/jail/%u` +
`ForceCommand internal-sftp` (sftp). Every user must be a managed account. The agent runs
`sshd -t`; on rejection the previous snippet is restored (or the new one removed). Reload is a
separate `service.action`.

## What was really verified (this sandbox, real kernel)
- cgroup v2 memory: a child in a 32 MB `memory.max` cgroup was OOM-killed (`oom_kill=1`).
- `pids.max=8`: forks beyond the limit failed with EAGAIN (5 started, 15 refused).
- Home isolation via `unshare -m` fallback (bwrap branch not exercised in that run).
- `bpanel-agent cage-exec` as root: process landed in
  `0::/bpanel.slice/bpanel-u.slice/bpanel-u-cagetest.slice`, ran as uid/gid 65534 with
  `NoNewPrivs: 1`; a non-account cgroup (`system.slice`) was refused (exit 126).
- `findmnt --verify` rollback path triggered once for real (an unresolvable UUID), which led to
  validating only the managed line.

## Not verified
- systemd is not PID 1 here: slice/FPM units, `systemd-run --slice` cron jobs and `daemon-reload`
  were never executed by a real systemd.
- hidepid remount of the real `/proc` was not performed (tests use temp fstab/mountinfo files).
- `sshd -t` tested with a fake binary only; the cage shell and sftp chroot were not run through a
  real sshd. The sftp chroot needs a root-owned `/var/lib/bpanel/jail/<user>` (not created yet).
- `cage-exec` joins the slice directory but does not write limits itself; without systemd, limits
  must already be written to that cgroup.

## Follow-ups
- Agent actions for cron (write scripts + cron.d per account) and API/UI for SSH jail mode.
- Create jail roots for sftp mode; `user-<uid>.slice` drop-ins so pam_systemd sessions get limits.
- Disk quota (DiskMB/InodeLimit via setquota) from the profile.
