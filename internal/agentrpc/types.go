// Package agentrpc defines the typed contract between the unprivileged API
// (bpanel-api) and the root agent (bpanel-agent). Every method has a fixed
// parameter struct; the agent never receives a shell string.
package agentrpc

import "encoding/json"

// Version of the wire contract. Bump when a struct changes incompatibly.
const Version = 1

// Request is one line of JSON on the agent socket.
type Request struct {
	V      int             `json:"v"`
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// Response is one line of JSON back.
type Response struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Method names (whitelist).
const (
	MPing             = "system.ping"
	MSysInfo          = "system.info"
	MAccountCreate    = "account.create"
	MAccountExists    = "account.exists"
	MAccountSuspend   = "account.suspend"
	MAccountTerminate = "account.terminate"
	MAccountPassword  = "account.password"
	MAccountQuota     = "account.quota"
	// MAccountQuotaBatch applies limits to many accounts with one systemd
	// daemon-reload (R2-PERF-9: package edits made one call and one reload
	// per account, 4-30 s).
	MAccountQuotaBatch = "account.quota.batch"
	MVhostApply        = "web.vhost.apply"
	MVhostRemove       = "web.vhost.remove"
	MPHPPoolApply      = "php.pool.apply"
	MPHPPoolRemove     = "php.pool.remove"
	MPHPVersions       = "php.versions"
	MPHPInstall        = "php.install"
	MDBCreate          = "db.create"
	MDBDrop            = "db.drop"
	MDBUserCreate      = "db.user.create"
	MDBUserDrop        = "db.user.drop"
	MDBUserPassword    = "db.user.password"
	MDBGrant           = "db.grant"
	MDBRevoke          = "db.revoke"
	MDBSizes           = "db.sizes"
	MDNSZoneCreate     = "dns.zone.create"
	MDNSZoneDelete     = "dns.zone.delete"
	MDNSZoneGet        = "dns.zone.get"
	MDNSRRSetReplace   = "dns.rrset.replace"
	MDNSRRSetDelete    = "dns.rrset.delete"
	MMailDomainOn      = "mail.domain.enable"
	MMailDomainOff     = "mail.domain.disable"
	MMailboxCreate     = "mail.box.create"
	MMailboxDelete     = "mail.box.delete"
	MMailboxPassword   = "mail.box.password"
	MMailboxQuota      = "mail.box.quota"
	MMailForwardSet    = "mail.forward.set"
	MMailForwardDel    = "mail.forward.delete"
	MMailUsage         = "mail.usage"
	MMailRootAlias     = "mail.root_alias"
	MFTPCreate         = "ftp.create"
	MFTPDelete         = "ftp.delete"
	MFTPPassword       = "ftp.password"
	MCronSet           = "cron.set"
	MSSLIssue          = "ssl.issue"
	MSSLSelfSigned     = "ssl.selfsigned"
	MSSLInfo           = "ssl.info"
	MServiceStatus     = "service.status"
	MServiceAction     = "service.action"
	MLogTail           = "log.tail"
	MDiskUsage         = "disk.usage"
	MFiles             = "files.op"
	MBackupRun         = "backup.run"
	MBackupList        = "backup.list"
	MBackupRestore     = "backup.restore"
)

type Empty struct{}

type PingResult struct {
	Version  string `json:"version"`
	Distro   string `json:"distro"`
	Hostname string `json:"hostname"`
}

type SysInfo struct {
	Hostname   string     `json:"hostname"`
	OS         string     `json:"os"`
	Kernel     string     `json:"kernel"`
	Arch       string     `json:"arch"`
	UptimeSec  int64      `json:"uptime_sec"`
	Load       [3]float64 `json:"load"`
	CPUs       int        `json:"cpus"`
	CPUModel   string     `json:"cpu_model"`
	CPUPercent float64    `json:"cpu_percent"`
	MemTotal   uint64     `json:"mem_total"`
	MemUsed    uint64     `json:"mem_used"`
	SwapTotal  uint64     `json:"swap_total"`
	SwapUsed   uint64     `json:"swap_used"`
	DiskTotal  uint64     `json:"disk_total"`
	DiskUsed   uint64     `json:"disk_used"`
	IPv4       []string   `json:"ipv4"`
	IPv6       []string   `json:"ipv6"`
	Processes  int        `json:"processes"`
}

// AccountCreate makes the Linux user, home layout, quota and limits.
type AccountCreate struct {
	User      string `json:"user"`
	Password  string `json:"password"`
	QuotaMB   int64  `json:"quota_mb"`    // 0 = unlimited
	CPUQuota  int    `json:"cpu_percent"` // 0 = unlimited (100 = one core)
	MemoryMB  int64  `json:"memory_mb"`
	MaxTasks  int    `json:"max_tasks"`
	ShellSFTP bool   `json:"sftp"` // allow SFTP (group bpanel-sftp)
	// Adopt lets the agent take over an existing account that carries the
	// panel's own ownership marker (left behind by a crash mid-create)
	// instead of refusing with user_exists (R2-PERF-15). Accounts without
	// the marker are never adopted.
	Adopt bool `json:"adopt,omitempty"`
}

type AccountCreateResult struct {
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Home string `json:"home"`
	// Created is true when this call made the Linux user. Rollback may only
	// terminate an account the agent created (SEC-5 / CODE-2).
	Created bool `json:"created"`
}

// AccountExistsResult tells the API whether a name is already taken on the
// host (/etc/passwd) and whether it is a panel-managed account.
type AccountExistsResult struct {
	Exists  bool `json:"exists"`
	Managed bool `json:"managed"`
}

type AccountRef struct {
	User string `json:"user"`
}

type AccountSuspend struct {
	User    string `json:"user"`
	Suspend bool   `json:"suspend"`
}

type AccountPassword struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type AccountQuota struct {
	User     string `json:"user"`
	QuotaMB  int64  `json:"quota_mb"`
	CPUQuota int    `json:"cpu_percent"`
	MemoryMB int64  `json:"memory_mb"`
	MaxTasks int    `json:"max_tasks"`
}

// AccountQuotaBatch is account.quota for many accounts.
type AccountQuotaBatch struct {
	Items []AccountQuota `json:"items"`
}

// AccountQuotaBatchResult names the accounts whose limits failed (user -> error code).
type AccountQuotaBatchResult struct {
	Failed map[string]string `json:"failed"`
}

// Vhost describes one site (a domain plus its aliases) for Nginx/Apache.
type Vhost struct {
	User       string   `json:"user"`
	Domain     string   `json:"domain"`
	Aliases    []string `json:"aliases"`
	DocRoot    string   `json:"docroot"` // relative to home, e.g. public_html
	PHPVersion string   `json:"php_version"`
	Mode       string   `json:"mode"` // "nginx" or "nginx-apache"
	SSL        bool     `json:"ssl"`
	Suspended  bool     `json:"suspended"`
	Redirect   string   `json:"redirect,omitempty"` // full URL; whole-site redirect
}

type DomainRef struct {
	Owner  string `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Domain string `json:"domain"`
}

type PHPPool struct {
	User         string            `json:"user"`
	Version      string            `json:"version"`
	MaxChildren  int               `json:"max_children"`
	MemoryLimit  string            `json:"memory_limit"`
	UploadMax    string            `json:"upload_max"`
	MaxExecution int               `json:"max_execution"`
	INI          map[string]string `json:"ini,omitempty"`
}

type PHPPoolRef struct {
	User    string `json:"user"`
	Version string `json:"version"`
}

type PHPVersion struct {
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Default   bool   `json:"default"`
	Unit      string `json:"unit"`
	Binary    string `json:"binary"`
}

type PHPVersionsResult struct {
	Versions []PHPVersion `json:"versions"`
}

type PHPInstall struct {
	Version string `json:"version"`
	Remove  bool   `json:"remove"`
}

// Owner (the hosting account) is optional on the wire for compatibility, but
// when set the agent enforces the "<owner>_" prefix on every name (CODE-27).
type DBRef struct {
	Owner string `json:"owner,omitempty"`
	Name  string `json:"name"`
}

type DBUser struct {
	Owner    string `json:"owner,omitempty"`
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"` // "localhost" by default
}

type DBUserRef struct {
	Owner string `json:"owner,omitempty"`
	User  string `json:"user"`
	Host  string `json:"host"`
}

type DBGrant struct {
	Owner      string   `json:"owner,omitempty"`
	DB         string   `json:"db"`
	User       string   `json:"user"`
	Host       string   `json:"host"`
	Privileges []string `json:"privileges"` // empty = ALL PRIVILEGES
}

type DBSizesReq struct {
	Prefix string `json:"prefix"`
}

type DBSizes struct {
	Sizes map[string]int64 `json:"sizes"`
}

type DNSRecord struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	TTL      int    `json:"ttl"`
	Content  string `json:"content"`
	Disabled bool   `json:"disabled,omitempty"`
}

type DNSZone struct {
	Owner   string      `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Zone    string      `json:"zone"`
	Records []DNSRecord `json:"records"`
	Serial  int64       `json:"serial,omitempty"`
	// Replace resets an existing zone's record sets in place (PATCH) instead
	// of failing with zone_exists. The zone itself (metadata, DNSSEC keys) is
	// never deleted and re-created.
	Replace bool `json:"replace,omitempty"`
}

type ZoneRef struct {
	Owner string `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Zone  string `json:"zone"`
}

type RRSet struct {
	Owner   string   `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Zone    string   `json:"zone"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

type RRSetRef struct {
	Owner string `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Zone  string `json:"zone"`
	Name  string `json:"name"`
	Type  string `json:"type"`
}

type MailDomain struct {
	User   string `json:"user"`
	Domain string `json:"domain"`
}

type MailDomainResult struct {
	DKIMSelector string `json:"dkim_selector"`
	DKIMRecord   string `json:"dkim_record"` // TXT content "v=DKIM1; k=rsa; p=..."
}

type Mailbox struct {
	User     string `json:"user"` // owning hosting account
	Email    string `json:"email"`
	Password string `json:"password"`
	QuotaMB  int64  `json:"quota_mb"`
}

type MailboxRef struct {
	User  string `json:"user"`
	Email string `json:"email"`
}

type MailForward struct {
	Owner        string   `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Source       string   `json:"source"`          // "info@example.com" or "@example.com" for catch-all
	Destinations []string `json:"destinations"`
}

type MailForwardRef struct {
	Owner  string `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Source string `json:"source"`
}

// RootAlias sets /etc/aliases "root: <email>" (panel contact email).
type RootAlias struct {
	Email string `json:"email"`
}

type MailUsageReq struct {
	User    string   `json:"user"`
	Domains []string `json:"domains"`
}

type MailUsage struct {
	Bytes map[string]int64 `json:"bytes"`
}

type FTPAccount struct {
	User     string `json:"user"` // owning hosting account
	Login    string `json:"login"`
	Password string `json:"password"`
	Dir      string `json:"dir"` // relative to home
	QuotaMB  int64  `json:"quota_mb"`
}

type FTPRef struct {
	Owner string `json:"owner,omitempty"` // owning hosting account, checked against the agent registry (CODE-27)
	Login string `json:"login"`
}

type CronEntry struct {
	Schedule [5]string `json:"schedule"`
	Command  string    `json:"command"`
}

type CronSet struct {
	User    string      `json:"user"`
	Email   string      `json:"email"`
	Entries []CronEntry `json:"entries"`
}

type SSLIssue struct {
	User    string   `json:"user"`
	Domain  string   `json:"domain"`
	SANs    []string `json:"sans"`
	Email   string   `json:"email"`
	Staging bool     `json:"staging"`
}

type SSLInfo struct {
	Domain     string   `json:"domain"`
	Present    bool     `json:"present"`
	Issuer     string   `json:"issuer"`
	NotAfter   string   `json:"not_after"`
	SANs       []string `json:"sans"`
	SelfSigned bool     `json:"self_signed"`
}

type ServiceStatusReq struct {
	Units []string `json:"units"`
}

type ServiceState struct {
	Unit        string `json:"unit"`
	Name        string `json:"name"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Enabled     string `json:"enabled"`
	MemoryBytes uint64 `json:"memory_bytes"`
	SinceUnix   int64  `json:"since_unix"`
}

type ServiceStatus struct {
	Services []ServiceState `json:"services"`
}

type ServiceAction struct {
	Unit   string `json:"unit"`
	Action string `json:"action"` // start|stop|restart|reload
}

type LogTail struct {
	User   string `json:"user"`
	Domain string `json:"domain"`
	Kind   string `json:"kind"` // access|error
	Lines  int    `json:"lines"`
}

type LogLines struct {
	Lines []string `json:"lines"`
}

type DiskUsageReq struct {
	User string `json:"user"`
}

type DiskEntry struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

type DiskUsage struct {
	TotalBytes int64       `json:"total_bytes"`
	Inodes     int64       `json:"inodes"`
	Entries    []DiskEntry `json:"entries"`
}

// FileOp is executed by a helper process running with the account's uid/gid,
// so the kernel enforces permissions on top of path confinement.
type FileOp struct {
	User    string   `json:"user"`
	Op      string   `json:"op"` // list|read|write|mkdir|touch|delete|rename|copy|chmod|zip|unzip|upload|download|write_chunk|read_chunk
	Path    string   `json:"path"`
	Paths   []string `json:"paths,omitempty"`
	Dest    string   `json:"dest,omitempty"`
	Content string   `json:"content,omitempty"` // text for write; base64 for upload/write_chunk
	Mode    uint32   `json:"mode,omitempty"`
	Offset  int64    `json:"offset,omitempty"` // write_chunk/read_chunk
	Length  int64    `json:"length,omitempty"` // read_chunk
}

type FileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	Perm    uint32 `json:"perm"`
	IsDir   bool   `json:"is_dir"`
	IsLink  bool   `json:"is_link"`
	ModUnix int64  `json:"mod_unix"`
}

type FileResult struct {
	Entries []FileEntry `json:"entries,omitempty"`
	Content string      `json:"content,omitempty"`
	Size    int64       `json:"size,omitempty"`
}

type BackupRun struct {
	User      string   `json:"user"`
	Databases []string `json:"databases"`
	Repo      string   `json:"repo,omitempty"` // empty = local default
	Tag       string   `json:"tag,omitempty"`
}

type BackupSnapshot struct {
	ID      string   `json:"id"`
	ShortID string   `json:"short_id"`
	Time    string   `json:"time"`
	Paths   []string `json:"paths"`
	Tags    []string `json:"tags"`
}

type BackupList struct {
	Snapshots []BackupSnapshot `json:"snapshots"`
}

type BackupRunResult struct {
	SnapshotIDs []string `json:"snapshot_ids"`
}

type BackupRestore struct {
	User     string `json:"user"`
	Snapshot string `json:"snapshot"`
	Path     string `json:"path"` // relative to home, "" = everything
	InPlace  bool   `json:"in_place"`
}

type BackupRestoreResult struct {
	RestoredTo string `json:"restored_to"`
}
