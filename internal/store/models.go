package store

// Row types. JSON tags are what the API returns.
//
// Limits (G1): -1 means unlimited, 0 means none (for counts), a positive
// number is the limit. Size limits (MB, percent, tasks) are never 0.

type Package struct {
	ID            int64  `db:"id" json:"id"`
	Name          string `db:"name" json:"name"`
	OwnerID       *int64 `db:"owner_id" json:"owner_id"`
	DiskMB        int64  `db:"disk_mb" json:"disk_mb"`
	BandwidthMB   int64  `db:"bandwidth_mb" json:"bandwidth_mb"`
	MaxDomains    int64  `db:"max_domains" json:"max_domains"`
	MaxSubdomains int64  `db:"max_subdomains" json:"max_subdomains"`
	MaxAliases    int64  `db:"max_aliases" json:"max_aliases"`
	MaxEmail      int64  `db:"max_email" json:"max_email"`
	MaxDB         int64  `db:"max_db" json:"max_db"`
	MaxFTP        int64  `db:"max_ftp" json:"max_ftp"`
	MailQuotaMB   int64  `db:"mail_quota_mb" json:"mail_quota_mb"`
	CPUPercent    int64  `db:"cpu_percent" json:"cpu_percent"`
	MemoryMB      int64  `db:"memory_mb" json:"memory_mb"`
	MaxTasks      int64  `db:"max_tasks" json:"max_tasks"`
	PHPVersion    string `db:"php_version" json:"php_version"`
	CreatedAt     int64  `db:"created_at" json:"created_at"`
	Version       int64  `db:"version" json:"version"` // optimistic locking (If-Match / "version")
	Accounts      int64  `db:"accounts" json:"accounts"`
}

type User struct {
	ID             int64  `db:"id" json:"id"`
	Username       string `db:"username" json:"username"`
	Role           string `db:"role" json:"role"`
	SecRole        string `db:"sec_role" json:"sec_role"` // v0.4 staff role on base admin ('' = super_admin)
	OwnerID        *int64 `db:"owner_id" json:"owner_id"`
	PackageID      *int64 `db:"package_id" json:"package_id"`
	Email          string `db:"email" json:"email"`
	PasswordHash   string `db:"password_hash" json:"-"`
	TOTPSecret     string `db:"totp_secret" json:"-"`
	TOTPEnabled    bool   `db:"totp_enabled" json:"totp_enabled"`
	TOTPLastStep   int64  `db:"totp_last_step" json:"-"`
	Lang           string `db:"lang" json:"lang"`
	Theme          string `db:"theme" json:"theme"`
	Status         string `db:"status" json:"status"`
	SuspendReason  string `db:"suspend_reason" json:"suspend_reason"`
	SystemUser     bool   `db:"system_user" json:"system_user"`
	UID            int64  `db:"uid" json:"uid"`
	Home           string `db:"home" json:"home"`
	PrimaryDomain  string `db:"primary_domain" json:"primary_domain"`
	PHPVersion     string `db:"php_version" json:"php_version"`
	WebMode        string `db:"web_mode" json:"web_mode"`
	MaxAccounts    int64  `db:"max_accounts" json:"max_accounts"`
	ResellerDiskMB int64  `db:"reseller_disk_mb" json:"reseller_disk_mb"`
	Favorites      string `db:"favorites" json:"-"` // JSON array of dashboard tool ids (GET /auth/me "favorites")
	LastLoginAt    int64  `db:"last_login_at" json:"last_login_at"`
	LastLoginIP    string `db:"last_login_ip" json:"last_login_ip"`
	CreatedAt      int64  `db:"created_at" json:"created_at"`
	Version        int64  `db:"version" json:"version"` // optimistic locking (If-Match / "version")
	PackageName    string `db:"package_name" json:"package_name"`
	OwnerName      string `db:"owner_name" json:"owner_name"`
}

type Domain struct {
	ID           int64  `db:"id" json:"id"`
	UserID       int64  `db:"user_id" json:"user_id"`
	Name         string `db:"name" json:"name"`
	Kind         string `db:"kind" json:"kind"`
	ParentID     *int64 `db:"parent_id" json:"parent_id"`
	DocRoot      string `db:"docroot" json:"docroot"`
	PHPVersion   string `db:"php_version" json:"php_version"`
	Redirect     string `db:"redirect" json:"redirect"`
	SSLStatus    string `db:"ssl_status" json:"ssl_status"`
	SSLExpires   string `db:"ssl_expires" json:"ssl_expires"`
	SSLAttemptAt int64  `db:"ssl_attempt_at" json:"ssl_attempt_at"`
	SSLError     string `db:"ssl_error" json:"ssl_error"`
	CreatedAt    int64  `db:"created_at" json:"created_at"`
	ParentName   string `db:"parent_name" json:"parent_name"`
}

type Database struct {
	ID        int64  `db:"id" json:"id"`
	UserID    int64  `db:"user_id" json:"user_id"`
	Name      string `db:"name" json:"name"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
	Users     string `db:"users" json:"users"`
	SizeBytes int64  `db:"-" json:"size_bytes"`
}

type DBUser struct {
	ID        int64  `db:"id" json:"id"`
	UserID    int64  `db:"user_id" json:"user_id"`
	Name      string `db:"name" json:"name"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
	DBs       string `db:"dbs" json:"dbs"`
}

type Mailbox struct {
	ID        int64  `db:"id" json:"id"`
	UserID    int64  `db:"user_id" json:"user_id"`
	DomainID  int64  `db:"domain_id" json:"domain_id"`
	Email     string `db:"email" json:"email"`
	QuotaMB   int64  `db:"quota_mb" json:"quota_mb"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
	UsedBytes int64  `db:"-" json:"used_bytes"`
}

type Forwarder struct {
	ID          int64  `db:"id" json:"id"`
	UserID      int64  `db:"user_id" json:"user_id"`
	Source      string `db:"source" json:"source"`
	Destination string `db:"destination" json:"destination"`
	CreatedAt   int64  `db:"created_at" json:"created_at"`
}

type FTPAccount struct {
	ID        int64  `db:"id" json:"id"`
	UserID    int64  `db:"user_id" json:"user_id"`
	Login     string `db:"login" json:"login"`
	Dir       string `db:"dir" json:"dir"`
	QuotaMB   int64  `db:"quota_mb" json:"quota_mb"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
}

type CronJob struct {
	ID        int64  `db:"id" json:"id"`
	UserID    int64  `db:"user_id" json:"user_id"`
	Minute    string `db:"minute" json:"minute"`
	Hour      string `db:"hour" json:"hour"`
	Dom       string `db:"dom" json:"dom"`
	Month     string `db:"month" json:"month"`
	Dow       string `db:"dow" json:"dow"`
	Command   string `db:"command" json:"command"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
}

type Session struct {
	IDHash         string `db:"id_hash"`
	UserID         int64  `db:"user_id"`
	ImpersonatorID int64  `db:"impersonator_id"`
	Realm          string `db:"realm"`
	CSRF           string `db:"csrf"`
	IP             string `db:"ip"`
	UserAgent      string `db:"user_agent"`
	CreatedAt      int64  `db:"created_at"`
	ExpiresAt      int64  `db:"expires_at"`
	LastSeen       int64  `db:"last_seen"`
	ReauthAt       int64  `db:"reauth_at"` // v0.4 step-up auth
}

type Audit struct {
	ID      int64  `db:"id" json:"id"`
	At      int64  `db:"at" json:"at"`
	ActorID int64  `db:"actor_id" json:"actor_id"`
	Actor   string `db:"actor" json:"actor"`
	IP      string `db:"ip" json:"ip"`
	Realm   string `db:"realm" json:"realm"`
	Action  string `db:"action" json:"action"`
	Target  string `db:"target" json:"target"`
	Detail  string `db:"detail" json:"detail"`
	OK      bool   `db:"ok" json:"ok"`
}
