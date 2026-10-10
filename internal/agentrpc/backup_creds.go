package agentrpc

// v0.4 backup part B: repository password / target credentials live in the
// panel's secret store (internal/secrets). The agent keeps them in memory only
// and hands them to restic through the child environment (RESTIC_PASSWORD),
// never on disk, never in logs. Retention is applied with backup.forget.

const (
	MBackupCredsExport = "backup.creds.export" // one-time migration: read the legacy 0600 password file
	MBackupCredsLoad   = "backup.creds.load"   // push the password (and target creds) into agent memory
	MBackupForget      = "backup.forget"       // restic forget --prune with a keep-* policy
)

// BackupCredsExport is the result of backup.creds.export. Found=false means no
// legacy password file exists for the account.
type BackupCredsExport struct {
	Found       bool              `json:"found"`
	Password    string            `json:"password,omitempty"`
	TargetCreds map[string]string `json:"target_creds,omitempty"`
}

// BackupCredsLoad carries secrets: callers must never log it.
type BackupCredsLoad struct {
	User        string            `json:"user"`
	Password    string            `json:"password"`
	TargetCreds map[string]string `json:"target_creds,omitempty"`
	// Retire removes the legacy password file once its content equals Password.
	Retire bool `json:"retire,omitempty"`
}

// String keeps the password out of %v / slog output.
func (BackupCredsLoad) String() string       { return "BackupCredsLoad{[redacted]}" }
func (BackupCredsExport) String() string     { return "BackupCredsExport{[redacted]}" }
func (c BackupCredsLoad) GoString() string   { return c.String() }
func (c BackupCredsExport) GoString() string { return c.String() }

type RetentionPolicy struct {
	Last    int `json:"keep_last"`
	Daily   int `json:"keep_daily"`
	Weekly  int `json:"keep_weekly"`
	Monthly int `json:"keep_monthly"`
	Yearly  int `json:"keep_yearly"`
}

type BackupForget struct {
	User   string          `json:"user"`
	Policy RetentionPolicy `json:"policy"`
}

type BackupForgetResult struct {
	Kept    int `json:"kept"`
	Removed int `json:"removed"`
}
