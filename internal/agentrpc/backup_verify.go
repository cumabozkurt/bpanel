package agentrpc

// v0.4 backup module: restore verification and admin snapshot deletion.
const (
	MBackupVerify = "backup.verify" // restore latest snapshot to temp + compare manifest + restic check
	MBackupDelete = "backup.delete" // forget --prune one snapshot (admin-only at the API)
)

type BackupVerify struct {
	User   string `json:"user"`
	Subset string `json:"subset,omitempty"` // restic check --read-data-subset, default 5%
}

type BackupVerification struct {
	User         string   `json:"user"`
	SnapshotID   string   `json:"snapshot_id"`
	Started      string   `json:"started"`
	Finished     string   `json:"finished"`
	FilesChecked int      `json:"files_checked"`
	Mismatches   int      `json:"mismatches"`
	CheckOK      bool     `json:"check_ok"`
	Status       string   `json:"status"`
	Error        string   `json:"error,omitempty"`
	Samples      []string `json:"mismatch_samples,omitempty"`
}

type BackupDelete struct {
	User     string `json:"user"`
	Snapshot string `json:"snapshot"`
}
