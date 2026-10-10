//go:build dev

package mockagent

import (
	"sync"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// BackupCredsState is the mock's view of v0.4 backup part B (tests inspect it).
var BackupCredsState = struct {
	sync.Mutex
	Legacy     map[string]string // pre-migration password files (user → password)
	Loaded     map[string]string // passwords pushed with backup.creds.load
	Retired    map[string]bool
	Forgets    map[string][]rpc.RetentionPolicy
	Exports    int
	FailForget map[string]bool
}{Legacy: map[string]string{}, Loaded: map[string]string{}, Retired: map[string]bool{}, Forgets: map[string][]rpc.RetentionPolicy{}, FailForget: map[string]bool{}}

func mockBackupCreds(method string, params any) (any, error) {
	st := &BackupCredsState
	st.Lock()
	defer st.Unlock()
	switch method {
	case rpc.MBackupCredsExport:
		var p rpc.AccountRef
		conv(params, &p)
		st.Exports++
		if pw, ok := st.Legacy[p.User]; ok {
			return rpc.BackupCredsExport{Found: true, Password: pw}, nil
		}
		return rpc.BackupCredsExport{}, nil
	case rpc.MBackupCredsLoad:
		var p rpc.BackupCredsLoad
		conv(params, &p)
		st.Loaded[p.User] = p.Password
		if p.Retire && st.Legacy[p.User] == p.Password {
			delete(st.Legacy, p.User)
			st.Retired[p.User] = true
		}
		return struct{}{}, nil
	default: // MBackupForget
		var p rpc.BackupForget
		conv(params, &p)
		if st.FailForget[p.User] {
			return nil, &rpc.Error{Code: "retention_failed", Message: "mock failure"}
		}
		st.Forgets[p.User] = append(st.Forgets[p.User], p.Policy)
		return rpc.BackupForgetResult{Kept: 1, Removed: 0}, nil
	}
}
