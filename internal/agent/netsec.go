// SPDX-License-Identifier: Apache-2.0

package agent

// v0.4 network security, part A: host firewall in the dedicated nftables
// table `inet bpanel` with safe apply + automatic rollback.
//
// netsec.fw.apply:
//  1. validates + renders the ruleset (internal/netsec, lockout guard),
//  2. `nft -c -f <file>` (check only),
//  3. snapshots the current table (`nft list table inet bpanel`),
//  4. persists {token, snapshot, deadline} to <NetsecDir>/pending.json,
//  5. `nft -f <file>` and arms a confirm timer (default 60 s).
//
// If netsec.fw.confirm(token) does not arrive in time the snapshot is
// restored. If the agent restarts while a change is pending, New() restores
// the snapshot immediately (netsecRecover). Without /usr/sbin/nft every
// action answers status "unsupported" and nothing is applied.
//
// nft runs through exec.CommandContext with argv only (run()), never a
// shell; the script is a root-owned 0600 file under NetsecDir.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/netsec"
)

var (
	// nftBins are the only nft binaries the agent will execute (no PATH lookup).
	nftBins = []string{"/usr/sbin/nft", "/sbin/nft"}
	// nftPrefix runs nft inside another network namespace (tests only),
	// e.g. {"sudo","-n","nsenter","-t",pid,"-n"}.
	nftPrefix []string
	// fwStates holds the per-agent firewall state (avoids touching Agent).
	fwStates sync.Map // *Agent -> *fwState
	// fwConfirmMin is the shortest confirm window (lowered in tests).
	fwConfirmMin = 10 * time.Second
)

const defaultNetsecDir = "/var/lib/bpanel/netsec"

type fwPending struct {
	Token    string    `json:"token"`
	Snapshot string    `json:"snapshot"`
	Deadline time.Time `json:"deadline"`
	AdminIP  string    `json:"admin_ip"`
}

type fwState struct {
	mu      sync.Mutex
	pending *fwPending
	timer   *time.Timer
}

func init() {
	for m, why := range map[string]string{
		rpc.MNetsecFwApply:   "server (host firewall, table inet bpanel only)",
		rpc.MNetsecFwConfirm: "server (confirms a pending firewall change)",
		rpc.MNetsecFwStatus:  "server (read-only probe)",
		rpc.MNetsecFwBlock:   "server (temporary IP block)",
		rpc.MNetsecFwUnblock: "server (removes a temporary IP block)",
		rpc.MNetsecFwList:    "server (read-only block list)",
	} {
		gateExempt[m] = why
	}
}

func (a *Agent) netsecRoutes() map[string]handler {
	m := map[string]handler{
		rpc.MNetsecFwApply:   bind(a.fwApply),
		rpc.MNetsecFwConfirm: bind(a.fwConfirm),
		rpc.MNetsecFwStatus:  bind(a.fwStatus),
		rpc.MNetsecFwBlock:   bind(a.fwBlock),
		rpc.MNetsecFwUnblock: bind(a.fwUnblock),
		rpc.MNetsecFwList:    bind(a.fwList),
	}
	for k, v := range a.netsecWafRoutes() { // part B (netsec_waf.go)
		m[k] = v
	}
	return m
}

func (a *Agent) fw() *fwState {
	v, _ := fwStates.LoadOrStore(a, &fwState{})
	return v.(*fwState)
}

func (a *Agent) netsecDir() string {
	if a.Cfg.NetsecDir != "" {
		return a.Cfg.NetsecDir
	}
	return defaultNetsecDir
}

func nftBin() string {
	for _, b := range nftBins {
		if fi, err := os.Stat(b); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return b
		}
	}
	return ""
}

func (a *Agent) nft(ctx context.Context, args ...string) (string, error) {
	bin := nftBin()
	if bin == "" {
		return "", errf("unsupported", "nft_not_installed")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	argv := append(append(append([]string{}, nftPrefix...), bin), args...)
	return run(cctx, nil, argv...)
}

func (a *Agent) fwWriteScript(name, script string) (string, error) {
	dir := a.netsecDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", errf("fw_state", "cannot create state dir")
	}
	p := filepath.Join(dir, name)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(script), 0o600); err != nil {
		return "", errf("fw_state", "cannot write script")
	}
	return p, os.Rename(tmp, p)
}

func (a *Agent) fwSavePending(p *fwPending) error {
	b, _ := json.Marshal(p)
	_, err := a.fwWriteScript("pending.json", string(b))
	return err
}

func (a *Agent) fwClearPending() { _ = os.Remove(filepath.Join(a.netsecDir(), "pending.json")) }

func (a *Agent) fwSetLastRollback(reason string) {
	_, _ = a.fwWriteScript("last_rollback", reason+" "+time.Now().UTC().Format(time.RFC3339))
}

// fwSnapshot returns the current table text, "" when it does not exist.
func (a *Agent) fwSnapshot(ctx context.Context) (string, error) {
	out, err := a.nft(ctx, "list", "table", "inet", "bpanel")
	if err != nil {
		if strings.Contains(out, "No such file or directory") || strings.Contains(err.Error(), "No such file or directory") {
			return "", nil
		}
		return "", errf("fw_snapshot", "cannot snapshot table inet bpanel")
	}
	return out, nil
}

func fwToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func netsecErr(err error) error {
	var e *netsec.Error
	if errors.As(err, &e) {
		return errf(e.Code, "%s", e.Msg)
	}
	return err
}

func (a *Agent) fwApply(ctx context.Context, p rpc.NetsecFwApplyParams) (rpc.NetsecFwApplyResult, error) {
	var res rpc.NetsecFwApplyResult
	confirm := time.Duration(p.ConfirmSeconds) * time.Second
	if p.ConfirmSeconds == 0 {
		confirm = 60 * time.Second
	}
	if confirm < fwConfirmMin || confirm > 600*time.Second {
		return res, errf("bad_params", "confirm_seconds must be 10..600")
	}
	script, err := netsec.Render(p.Ruleset, time.Now())
	if err != nil {
		return res, netsecErr(err)
	}
	res.Script = script
	if err := netsec.SyntaxCheck(script); err != nil {
		return res, netsecErr(err)
	}
	res.SyntaxOK = true
	if nftBin() == "" {
		res.Status, res.Reason = "unsupported", "nft_not_installed"
		return res, nil
	}
	st := a.fw()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pending != nil {
		return res, errf("fw_pending", "another firewall change is waiting for confirmation")
	}
	path, err := a.fwWriteScript("next.nft", script)
	if err != nil {
		return res, err
	}
	if _, err := a.nft(ctx, "-c", "-f", path); err != nil {
		return res, errf("fw_invalid", "nft rejected the ruleset (check only)")
	}
	snap, err := a.fwSnapshot(ctx)
	if err != nil {
		return res, err
	}
	pend := &fwPending{Token: fwToken(), Snapshot: snap, Deadline: time.Now().Add(confirm), AdminIP: p.Ruleset.AdminIP}
	if err := a.fwSavePending(pend); err != nil {
		return res, err
	}
	if _, err := a.nft(ctx, "-f", path); err != nil {
		a.fwClearPending()
		return res, errf("fw_apply_failed", "nft could not apply the ruleset; table unchanged")
	}
	st.pending = pend
	tok := pend.Token
	st.timer = time.AfterFunc(confirm, func() { a.fwRollback(tok, "timeout") })
	a.Log.Info("netsec firewall applied, awaiting confirm", "deadline", pend.Deadline)
	res.Status, res.Token, res.Deadline = "pending", pend.Token, pend.Deadline
	return res, nil
}

// fwRollback restores the snapshot of the pending change named by token.
func (a *Agent) fwRollback(token, reason string) {
	st := a.fw()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pending == nil || st.pending.Token != token {
		return
	}
	a.fwRestoreLocked(st.pending, reason)
	st.pending, st.timer = nil, nil
}

func (a *Agent) fwRestoreLocked(p *fwPending, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	path, err := a.fwWriteScript("rollback.nft", netsec.RestoreScript(p.Snapshot))
	if err == nil {
		_, err = a.nft(ctx, "-f", path)
	}
	if err != nil {
		// keep pending.json so the next start retries the rollback
		a.Log.Error("netsec firewall rollback failed", "reason", reason)
		return
	}
	a.fwClearPending()
	a.fwSetLastRollback(reason)
	a.Log.Warn("netsec firewall change rolled back", "reason", reason)
}

// netsecRecover rolls back a change left pending by a previous agent
// process (called from New).
func (a *Agent) netsecRecover() {
	b, err := os.ReadFile(filepath.Join(a.netsecDir(), "pending.json"))
	if err != nil {
		return
	}
	var p fwPending
	if json.Unmarshal(b, &p) != nil || p.Token == "" {
		a.fwClearPending()
		return
	}
	if nftBin() == "" {
		return
	}
	st := a.fw()
	st.mu.Lock()
	defer st.mu.Unlock()
	a.fwRestoreLocked(&p, "agent_restart")
}

func (a *Agent) fwConfirm(ctx context.Context, p rpc.NetsecFwConfirmParams) (rpc.NetsecFwConfirmResult, error) {
	st := a.fw()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pending == nil || subtle.ConstantTimeCompare([]byte(st.pending.Token), []byte(p.Token)) != 1 {
		return rpc.NetsecFwConfirmResult{}, errf("fw_no_pending", "no pending change with this token (expired or rolled back)")
	}
	if st.timer != nil {
		st.timer.Stop()
	}
	_, _ = a.fwWriteScript("admin_ip", st.pending.AdminIP)
	st.pending, st.timer = nil, nil
	a.fwClearPending()
	a.Log.Info("netsec firewall change confirmed")
	return rpc.NetsecFwConfirmResult{Status: "confirmed"}, nil
}

func (a *Agent) fwStatus(ctx context.Context, _ rpc.NetsecFwStatusParams) (rpc.NetsecFwStatusResult, error) {
	var r rpc.NetsecFwStatusResult
	r.Supported = nftBin() != ""
	if !r.Supported {
		r.Reason = "nft_not_installed"
	}
	st := a.fw()
	st.mu.Lock()
	if st.pending != nil {
		r.Pending, r.Deadline = true, st.pending.Deadline
	}
	st.mu.Unlock()
	if b, err := os.ReadFile(filepath.Join(a.netsecDir(), "last_rollback")); err == nil {
		r.LastRollback = strings.Fields(string(b) + " ")[0]
	}
	return r, nil
}

func (a *Agent) fwAdminIP(given string) string {
	if given != "" {
		return given
	}
	b, _ := os.ReadFile(filepath.Join(a.netsecDir(), "admin_ip"))
	return strings.TrimSpace(string(b))
}

func (a *Agent) fwBlock(ctx context.Context, p rpc.NetsecFwBlockParams) (rpc.NetsecFwBlockResult, error) {
	set, el, err := netsec.BlockElement(p.IP, time.Duration(p.TimeoutSeconds)*time.Second, a.fwAdminIP(p.AdminIP))
	if err != nil {
		return rpc.NetsecFwBlockResult{}, netsecErr(err)
	}
	if nftBin() == "" {
		return rpc.NetsecFwBlockResult{Status: "unsupported", Reason: "nft_not_installed"}, nil
	}
	if _, err := a.nft(ctx, "add", "element", "inet", "bpanel", set, "{ "+el+" }"); err != nil {
		return rpc.NetsecFwBlockResult{}, errf("fw_block_failed", "nft could not add the block (is the firewall applied?)")
	}
	a.Log.Info("netsec block added", "set", set)
	return rpc.NetsecFwBlockResult{Status: "ok"}, nil
}

func (a *Agent) fwUnblock(ctx context.Context, p rpc.NetsecFwUnblockParams) (rpc.NetsecFwBlockResult, error) {
	set, el, err := netsec.UnblockElement(p.IP)
	if err != nil {
		return rpc.NetsecFwBlockResult{}, netsecErr(err)
	}
	if nftBin() == "" {
		return rpc.NetsecFwBlockResult{Status: "unsupported", Reason: "nft_not_installed"}, nil
	}
	if out, err := a.nft(ctx, "delete", "element", "inet", "bpanel", set, "{ "+el+" }"); err != nil {
		if strings.Contains(out+err.Error(), "No such file or directory") {
			return rpc.NetsecFwBlockResult{Status: "ok"}, nil // already gone (expired)
		}
		return rpc.NetsecFwBlockResult{}, errf("fw_unblock_failed", "nft could not remove the block")
	}
	return rpc.NetsecFwBlockResult{Status: "ok"}, nil
}

func (a *Agent) fwList(ctx context.Context, _ rpc.NetsecFwListParams) (rpc.NetsecFwListResult, error) {
	res := rpc.NetsecFwListResult{Blocks: []netsec.Block{}}
	if nftBin() == "" {
		res.Status, res.Reason = "unsupported", "nft_not_installed"
		return res, nil
	}
	now := time.Now()
	for _, set := range []string{"block4", "block6"} {
		out, err := a.nft(ctx, "-j", "list", "set", "inet", "bpanel", set)
		if err != nil {
			if strings.Contains(out+err.Error(), "No such file or directory") {
				continue
			}
			return res, errf("fw_list_failed", "nft could not list %s", set)
		}
		bs, err := netsec.ParseSetJSON([]byte(out), now)
		if err != nil {
			return res, errf("fw_list_failed", "unexpected nft output")
		}
		res.Blocks = append(res.Blocks, bs...)
	}
	res.Status = "ok"
	return res, nil
}
