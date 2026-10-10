package api

// v0.4 backup part B: the restic repository password of every account and the
// backup target credentials live in the secret store (internal/secrets,
// records "backup/repo/<user>" and "backup/target"). Before every backup.*
// agent call the panel pushes them with backup.creds.load; the agent keeps
// them in memory and gives restic only RESTIC_PASSWORD in the child env.
// One-time, idempotent migration: the legacy root 0600 password file is
// exported once, stored, and retired by the agent when the stored value
// equals the file. Secrets never appear in logs, audit details or errors.
//
// If the secret store is unavailable (master key unreadable) backups keep
// using the legacy file so a broken key file never makes repositories
// unreadable; this is logged (without values).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/secrets"
)

const (
	backupRepoSecretPrefix = "backup/repo/"
	backupTargetSecret     = "backup/target"
)

var backupCredsMu sync.Mutex // serialises first-time migration per process

func backupRepoSecret(user string) string { return backupRepoSecretPrefix + user }

func (s *Server) secretsUsable() (secrets.SecretStore, bool) {
	st := s.Secrets()
	_, bad := st.(unavailableStore)
	return st, !bad
}

// backupPassword returns the account's repository password from the secret
// store, migrating it from the agent's legacy file (or generating a new one
// for an account without one) the first time. Idempotent.
func (s *Server) backupPassword(ctx context.Context, user string) (string, bool, error) {
	st, ok := s.secretsUsable()
	if !ok {
		return "", false, errSecretsUnavailable
	}
	if b, err := st.Get(ctx, backupRepoSecret(user)); err == nil {
		return string(b), false, nil
	} else if !errors.Is(err, secrets.ErrNotFound) {
		return "", false, err
	}
	backupCredsMu.Lock()
	defer backupCredsMu.Unlock()
	if b, err := st.Get(ctx, backupRepoSecret(user)); err == nil {
		return string(b), false, nil
	}
	var ex rpc.BackupCredsExport
	if err := s.Agent.Call(ctx, rpc.MBackupCredsExport, rpc.AccountRef{User: user}, &ex); err != nil {
		return "", false, err
	}
	pw := ex.Password
	if !ex.Found || pw == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", false, err
		}
		pw = hex.EncodeToString(b)
	}
	if err := st.Put(ctx, backupRepoSecret(user), []byte(pw)); err != nil {
		return "", false, err
	}
	if len(ex.TargetCreds) > 0 {
		if _, err := st.Get(ctx, backupTargetSecret); errors.Is(err, secrets.ErrNotFound) {
			if b, err := json.Marshal(ex.TargetCreds); err == nil {
				_ = st.Put(ctx, backupTargetSecret, b)
			}
		}
	}
	if s.Log != nil {
		s.Log.Info("backup password moved to secret store", "user", user, "from_legacy_file", ex.Found)
	}
	return pw, true, nil
}

func (s *Server) backupTargetCreds(ctx context.Context) map[string]string {
	st, ok := s.secretsUsable()
	if !ok {
		return nil
	}
	b, err := st.Get(ctx, backupTargetSecret)
	if err != nil {
		return nil
	}
	var m map[string]string
	_ = json.Unmarshal(b, &m)
	return m
}

// loadBackupCreds pushes the account's secrets into agent memory. With an
// unavailable secret store it is a no-op (legacy file path).
func (s *Server) loadBackupCreds(ctx context.Context, user string) error {
	pw, _, err := s.backupPassword(ctx, user)
	if errors.Is(err, errSecretsUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.Agent.Call(ctx, rpc.MBackupCredsLoad, rpc.BackupCredsLoad{User: user, Password: pw, TargetCreds: s.backupTargetCreds(ctx), Retire: true}, nil)
}

// preBackupCall is invoked by agentCall for every backup.* method that acts
// on an account's repository.
func (s *Server) preBackupCall(ctx context.Context, method string, params any) error {
	switch method {
	case rpc.MBackupRun, rpc.MBackupList, rpc.MBackupRestore, rpc.MBackupVerify, rpc.MBackupDelete, rpc.MBackupForget:
	default:
		return nil
	}
	b, _ := json.Marshal(params)
	var ref struct {
		User string `json:"user"`
	}
	if json.Unmarshal(b, &ref) != nil || ref.User == "" {
		return nil
	}
	return s.loadBackupCreds(ctx, ref.User)
}

// migrateBackupSecrets runs once at housekeeping start: every active account
// gets its repository password in the secret store and the legacy file is
// retired. Safe to run repeatedly.
func (s *Server) migrateBackupSecrets(ctx context.Context) (moved int) {
	if _, ok := s.secretsUsable(); !ok {
		if s.Log != nil {
			s.Log.Warn("backup secrets migration skipped: secret store unavailable")
		}
		return 0
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT username FROM users WHERE role='user' AND status<>'deleted' ORDER BY id`)
	if err != nil {
		return 0
	}
	var users []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			users = append(users, u)
		}
	}
	rows.Close()
	for _, u := range users {
		_, m, err := s.backupPassword(ctx, u)
		if err != nil {
			if s.Log != nil {
				s.Log.Warn("backup secrets migration", "user", u, "code", agentCode(err))
			}
			continue
		}
		if m {
			moved++
		}
		if err := s.loadBackupCreds(ctx, u); err != nil && s.Log != nil {
			s.Log.Warn("backup creds load", "user", u, "code", agentCode(err))
		}
	}
	return moved
}

// ---- secrets rotate API ----------------------------------------------------------------

func (s *Server) mountSecretsRotate(r chi.Router) {
	s.opPermReauth(r, rbac.SecretsRotate, "POST", "/admin/secrets/rotate", "security",
		"Rotate the secret store master key (super_admin, recent auth); returns the new key id", nil, s.h(s.rotateSecrets))
}

func (s *Server) rotateSecrets(w http.ResponseWriter, r *http.Request) (any, error) {
	if roleOf(r) != rbac.SuperAdmin || tokenOf(r) != nil {
		return nil, &apiError{Status: 403, Code: "permission_denied"}
	}
	st, ok := s.secretsUsable()
	if !ok {
		s.audit(r, "secrets.rotate", "", "secrets_unavailable", false)
		return nil, errSecretsUnavailable
	}
	old, _ := st.Status()["key_id"].(string)
	n, err := st.Rotate(r.Context())
	if err != nil {
		s.audit(r, "secrets.rotate", old, "rotate_failed", false)
		return nil, &apiError{Status: 500, Code: "rotate_failed"}
	}
	kid, _ := st.Status()["key_id"].(string)
	s.audit(r, "secrets.rotate", kid, fmt.Sprintf("from %s, %d records re-encrypted", old, n), true)
	return map[string]any{"key_id": kid, "previous_key_id": old, "reencrypted": n}, nil
}
