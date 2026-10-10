package installer

// Systemd units (also shipped in packaging/systemd; a test keeps them equal).

// UnitAgent runs the root agent. It has to stay root with broad file-system
// access (it manages /etc, /home, /var, packages, users and quotas), so the
// hardening removes what it never needs: kernel modules/tunables/logs, the
// clock, raw I/O, swap, reboot, ptrace, realtime, personality changes, and
// every capability outside the list below. `systemd-analyze security`
// drops from 9.0 UNSAFE to 5.4 MEDIUM (systemd 257, --offline); see audit/fixlog-installer.md.
//
// Kept capabilities and why:
//
//	CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID  manage files of every account
//	SETUID SETGID SETPCAP                            useradd/chpasswd/runuser, dpkg sandbox (_apt)
//	KILL                                             pkill on suspend/terminate
//	NET_ADMIN                                        nft blocklist updates
//	SYS_ADMIN                                        quotactl(2) (setquota), mount namespaces of tools
//	SYS_RESOURCE                                     setquota above soft limits, rlimits of children
//	AUDIT_WRITE                                      PAM/shadow tools write audit records
//	SETFCAP MKNOD                                    package installs (php.install) set file caps
//	IPC_LOCK                                         gpg/apt key handling (mlock)
//	NET_BIND_SERVICE                                 maintainer scripts that briefly bind low ports
//	SYS_CHROOT                                       dpkg/rpm --root helpers, sftp chroot tests
const UnitAgent = `[Unit]
Description=BOZKURT PANEL agent (root, unix socket only)
After=network.target
Before=bpanel-api.service

[Service]
Type=simple
# Remove stale restic locks left by a killed backup (R2-PERF-14). Only the
# agent runs restic, so no lock can be live while it is stopped. Never fatal.
ExecStartPre=-/usr/local/lib/bpanel/bpanel-installer restic-unlock
ExecStart=/usr/local/bin/bpanel-agent --config /etc/bpanel/agent.json
Restart=always
RestartSec=2
RuntimeDirectory=bpanel
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
UMask=0022
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_KILL CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_AUDIT_WRITE CAP_SETFCAP CAP_MKNOD CAP_IPC_LOCK CAP_NET_BIND_SERVICE CAP_SYS_CHROOT
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectClock=yes
ProtectHostname=yes
PrivateTmp=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=~user
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @obsolete @raw-io @reboot @swap
SystemCallErrorNumber=EPERM
KeyringMode=private

[Install]
WantedBy=multi-user.target
`

// UnitAPI runs the unprivileged API.
const UnitAPI = `[Unit]
Description=BOZKURT PANEL API and web interface (ports 2082/2083, 2086/2087)
After=network-online.target bpanel-agent.service
Wants=network-online.target bpanel-agent.service

[Service]
Type=simple
User=bpanel
Group=bpanel
ExecStart=/usr/local/bin/bpanel-api --config /etc/bpanel/api.json
Restart=always
RestartSec=2
# Memory ceiling (R2-PERF-1): the Go GC works hard below GOMEMLIMIT, the
# kernel throttles at MemoryHigh and kills only this unit at MemoryMax,
# never MariaDB or a PHP pool.
Environment=GOMEMLIMIT=256MiB
MemoryHigh=384M
MemoryMax=512M
UMask=0027
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/bpanel /var/log/bpanel
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
`

// UnitFirewall loads the panel nftables table at boot.
const UnitFirewall = `[Unit]
Description=BOZKURT PANEL firewall (nftables table inet bpanel)
Wants=network-pre.target
Before=network-pre.target shutdown.target
After=nftables.service
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/bpanel/nftables.conf
ExecReload=/usr/sbin/nft -f /etc/bpanel/nftables.conf
ExecStop=/usr/sbin/nft delete table inet bpanel

[Install]
WantedBy=multi-user.target
`
