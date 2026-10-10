// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 BPanel Shield: policy API (GET/PUT /admin/shield/policies).
//
// Rows of shield_policies are either global (account_id NULL) or per account.
// The effective policy of an account = shield.DefaultPolicy(), overridden by
// global rows, overridden by the account's rows (see shieldPolicy). An empty
// action means "inherit".
//
// Scope rules:
//   - admin / super_admin (shield.write): global and any account.
//   - reseller (shield.write, account scoped): only accounts it owns
//     (users.owner_id); global rows are read-only for it; and for the risky
//     classes (script, executable) it may never set an action weaker than the
//     effective global one (strictness allow_with_warning < hold < quarantine =
//     block). Infected files are always quarantined/blocked and are not
//     configurable here.
//   - archive rows have no on_unavailable of their own (an archive that
//     cannot be scanned follows the script rule), so it must be empty.

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/shield"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// ShieldPolicyRow is one shield_policies row.
type ShieldPolicyRow struct {
	FileClass     string `json:"file_class"`
	OnUnavailable string `json:"on_unavailable"`
	OnSuspicious  string `json:"on_suspicious"`
}

// ShieldPolicySet is the stored rows of one scope (account_id nil = global).
type ShieldPolicySet struct {
	AccountID *int64            `json:"account_id"`
	Account   string            `json:"account,omitempty"`
	Rows      []ShieldPolicyRow `json:"rows"`
	UpdatedAt int64             `json:"updated_at,omitempty"`
}

// ShieldPolicyPut replaces the rows of one scope. Classes left out are
// deleted (inherit).
type ShieldPolicyPut struct {
	AccountID *int64            `json:"account_id"`
	Rows      []ShieldPolicyRow `json:"rows"`
}

var (
	shieldClasses      = map[string]bool{"script": true, "executable": true, "archive": true, "other": true}
	shieldOnUnavailble = map[string]bool{"": true, "allow_with_warning": true, "block": true, "hold": true}
	shieldOnSuspicious = map[string]bool{"": true, "allow_with_warning": true, "block": true, "quarantine": true, "hold": true}
)

// shieldStrictness orders actions from weakest to strictest.
func shieldStrictness(a string) int {
	switch a {
	case "allow", "allow_with_warning":
		return 0
	case "hold":
		return 1
	case "quarantine", "block":
		return 2
	}
	return -1
}

func (s *Server) mountShieldPolicies(r chi.Router) {
	s.opPerm(r, rbac.ShieldRead, "GET", "/admin/shield/policies", "shield", "Shield policies: defaults, global rows and per-account rows in scope", nil, s.h(s.getShieldPolicies))
	s.opPerm(r, rbac.ShieldWrite, "PUT", "/admin/shield/policies", "shield", "Replace the Shield policy rows of the global scope (admin) or one account", ShieldPolicyPut{}, s.h(s.putShieldPolicies))
}

// validateShieldRows checks enums and duplicates (pure; no scope rules).
func validateShieldRows(rows []ShieldPolicyRow) error {
	seen := map[string]bool{}
	for _, row := range rows {
		if !shieldClasses[row.FileClass] {
			return badMsg("shield_policy_invalid", "file_class")
		}
		if seen[row.FileClass] {
			return badMsg("shield_policy_invalid", "duplicate file_class "+row.FileClass)
		}
		seen[row.FileClass] = true
		if !shieldOnUnavailble[row.OnUnavailable] {
			return badMsg("shield_policy_invalid", "on_unavailable")
		}
		if !shieldOnSuspicious[row.OnSuspicious] {
			return badMsg("shield_policy_invalid", "on_suspicious")
		}
		if row.FileClass == "archive" && row.OnUnavailable != "" {
			return badMsg("shield_policy_invalid", "archive on_unavailable follows the script rule; leave it empty")
		}
	}
	return nil
}

// checkNotWeaker refuses rows that weaken the global policy for risky classes.
func checkNotWeaker(rows []ShieldPolicyRow, global shield.AccountPolicy) error {
	for _, row := range rows {
		if row.FileClass != "script" && row.FileClass != "executable" {
			continue
		}
		if row.OnUnavailable != "" && shieldStrictness(row.OnUnavailable) < shieldStrictness(string(global.OnUnavailableScript)) {
			return &apiError{Status: 403, Code: "shield_policy_weaker", Message: row.FileClass + " on_unavailable below global " + string(global.OnUnavailableScript)}
		}
		if row.OnSuspicious != "" && shieldStrictness(row.OnSuspicious) < shieldStrictness(string(global.OnSuspiciousScript)) {
			return &apiError{Status: 403, Code: "shield_policy_weaker", Message: row.FileClass + " on_suspicious below global " + string(global.OnSuspiciousScript)}
		}
	}
	return nil
}

func (s *Server) getShieldPolicies(w http.ResponseWriter, r *http.Request) (any, error) {
	me := userOf(r)
	ctx := r.Context()
	q := `SELECT p.account_id, IFNULL(u.username,''), p.file_class, p.on_unavailable, p.on_suspicious, p.updated_at
		FROM shield_policies p LEFT JOIN users u ON u.id=p.account_id`
	var args []any
	if me.Role == "reseller" {
		q += ` WHERE p.account_id IS NULL OR p.account_id IN (SELECT id FROM users WHERE owner_id=?)`
		args = append(args, me.ID)
	}
	q += ` ORDER BY p.account_id IS NOT NULL, u.username, p.file_class`
	rows, err := s.Store.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	global := ShieldPolicySet{Rows: []ShieldPolicyRow{}}
	accounts := []*ShieldPolicySet{}
	byID := map[int64]*ShieldPolicySet{}
	for rows.Next() {
		var aid sql.NullInt64
		var name string
		var row ShieldPolicyRow
		var ts int64
		if err := rows.Scan(&aid, &name, &row.FileClass, &row.OnUnavailable, &row.OnSuspicious, &ts); err != nil {
			return nil, err
		}
		set := &global
		if aid.Valid {
			if set = byID[aid.Int64]; set == nil {
				id := aid.Int64
				set = &ShieldPolicySet{AccountID: &id, Account: name}
				byID[id] = set
				accounts = append(accounts, set)
			}
		}
		set.Rows = append(set.Rows, row)
		if ts > set.UpdatedAt {
			set.UpdatedAt = ts
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return map[string]any{
		"defaults":         shield.DefaultPolicy(),
		"effective_global": s.shieldPolicy(ctx, 0),
		"global":           global,
		"accounts":         accounts,
		"can_edit_global":  me.Role != "reseller",
		"enums": map[string]any{
			"file_class":     []string{"script", "executable", "archive", "other"},
			"on_unavailable": []string{"", "allow_with_warning", "hold", "block"},
			"on_suspicious":  []string{"", "allow_with_warning", "hold", "quarantine", "block"},
		},
	}, nil
}

// shieldPolicyAccount checks the target account exists, is a hosting
// account and is in the caller's scope.
func (s *Server) shieldPolicyAccount(ctx context.Context, me *store.User, id int64) error {
	var owner sql.NullInt64
	var role string
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT owner_id, role FROM users WHERE id=?`, id).Scan(&owner, &role); err != nil {
		return notFound()
	}
	if role == "admin" || role == "super_admin" || role == "reseller" {
		return badMsg("shield_policy_invalid", "account_id is not a hosting account")
	}
	if me.Role == "reseller" && (!owner.Valid || owner.Int64 != me.ID) {
		return notFound() // do not reveal accounts outside the scope
	}
	return nil
}

func (s *Server) putShieldPolicies(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ShieldPolicyPut
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	me := userOf(r)
	ctx := r.Context()
	if err := validateShieldRows(in.Rows); err != nil {
		return nil, err
	}
	target := "global"
	if in.AccountID == nil {
		if me.Role == "reseller" {
			return nil, forbidden()
		}
	} else {
		if err := s.shieldPolicyAccount(ctx, me, *in.AccountID); err != nil {
			return nil, err
		}
		if me.Role == "reseller" {
			if err := checkNotWeaker(in.Rows, s.shieldPolicy(ctx, 0)); err != nil {
				return nil, err
			}
		}
		target = "account:" + strconv.FormatInt(*in.AccountID, 10)
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var aid any
	if in.AccountID != nil {
		aid = *in.AccountID
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM shield_policies WHERE IFNULL(account_id,0)=IFNULL(?,0)`, aid); err != nil {
		return nil, err
	}
	now := s.Now().Unix()
	for _, row := range in.Rows {
		if row.OnUnavailable == "" && row.OnSuspicious == "" {
			continue // fully inherited: no row
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO shield_policies(account_id, file_class, on_unavailable, on_suspicious, updated_at) VALUES (?,?,?,?,?)`,
			aid, row.FileClass, row.OnUnavailable, row.OnSuspicious, now); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.audit(r, "shield.policy_update", target, "", true)
	return s.getShieldPolicies(w, r)
}
