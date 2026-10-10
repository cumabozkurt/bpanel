// SPDX-License-Identifier: Apache-2.0

package agent

// BPanel Shield agent actions (v0.4): on-demand scans, quarantine, the
// upload staging pipeline and the real-time watcher. Everything that
// happens is appended to a JSONL journal (<ShieldDir>/journal.jsonl); the
// panel pulls it with shield.events and stores it in its database.
//
// Upload pipeline: the API streams the upload into a root-owned staging file
// (<ShieldDir>/staging/<user>/<id>, 0600) with shield.stage.chunk, then
// shield.stage.commit scans it, applies the account policy and either places
// it as the account user (files helper: write_chunk + rename, so ownership
// and the home-confinement rules are the same as any file-manager write) or
// refuses it (block) / moves it to the encrypted quarantine (quarantine,
// hold). The account never sees an unscanned byte.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/fileops"
	"github.com/cumabozkurt/bpanel/internal/shield"
)

// DefaultShieldDir is the Shield state directory (quarantine, journal, staging, queue).
const DefaultShieldDir = "/var/lib/bpanel/shield"

func init() {
	for _, m := range []string{rpc.MShieldScan, rpc.MShieldStageChunk, rpc.MShieldStageCommit, rpc.MShieldStageAbort,
		rpc.MShieldQRestore, rpc.MShieldQDelete, rpc.MShieldQFP} {
		accountField[m] = struct {
			key      string
			optional bool
		}{"user", false}
	}
	accountField[rpc.MShieldQList] = struct {
		key      string
		optional bool
	}{"user", true} // empty = every account (admin view)
	gateExempt[rpc.MShieldStatus] = "server (engine/coverage health, no parameters naming an account)"
	gateExempt[rpc.MShieldEvents] = "server (journal read; the panel filters by account ownership)"
}

func (a *Agent) shieldRoutes() map[string]handler {
	return map[string]handler{
		rpc.MShieldScan:        bind(a.shieldScan),
		rpc.MShieldQList:       bind(a.shieldQList),
		rpc.MShieldQRestore:    bind(a.shieldQRestore),
		rpc.MShieldQDelete:     bind(a.shieldQDelete),
		rpc.MShieldQFP:         bind(a.shieldQFP),
		rpc.MShieldStatus:      bind(a.shieldStatus),
		rpc.MShieldEvents:      bind(a.shieldEvents),
		rpc.MShieldStageChunk:  bind(a.shieldStageChunk),
		rpc.MShieldStageCommit: bind(a.shieldStageCommit),
		rpc.MShieldStageAbort:  bind(a.shieldStageAbort),
	}
}

// shieldState is created lazily (first shield action or StartShield).
type shieldState struct {
	dir     string
	scanner *shield.Scanner
	all     []shield.MalwareScannerProvider // every known engine (status)
	q       *shield.Quarantine
	jmu     sync.Mutex
	seq     int64
	watcher *shield.Watcher
	queue   *shield.Queue
	rtState string // on | off | degraded | unsupported
	rtWhy   string
}

// Test hooks.
var (
	// shieldEngines builds the engine list: the builtin heuristic always;
	// clamd when its socket exists; yara when the binary is installed. An
	// engine that is configured but stops answering yields
	// scanner_unavailable (fail closed), a not-installed one is skipped and
	// reported as not_installed by shield.status.
	shieldEngines = func(dir string) (active, all []shield.MalwareScannerProvider) {
		h := &shield.Heuristic{}
		c := shield.NewClamd(shield.DefaultClamdAddr)
		active = []shield.MalwareScannerProvider{h}
		var y *shield.Yara
		if rules, err := shield.WriteBuiltinRules(filepath.Join(dir, "rules")); err == nil {
			y = shield.NewYara(rules)
		}
		all = []shield.MalwareScannerProvider{h, c}
		if _, err := os.Stat(strings.TrimPrefix(shield.DefaultClamdAddr, "unix:")); err == nil {
			active = append(active, c)
		}
		if y != nil {
			all = append(all, y)
			if _, err := exec.LookPath("yara"); err == nil {
				active = append(active, y)
			}
		}
		return active, all
	}
	// shieldPlace writes the staged file into the account home as the
	// account user. Default: files helper (write_chunk to a temp name, rename).
	shieldPlace func(a *Agent, ctx context.Context, user, staged, rel string) error = placeViaHelper
)

func (a *Agent) shieldDir() string {
	if a.Cfg.ShieldDir != "" {
		return a.Cfg.ShieldDir
	}
	return DefaultShieldDir
}

func (a *Agent) sh() (*shieldState, error) {
	a.shMu.Lock()
	defer a.shMu.Unlock()
	if a.shState != nil {
		return a.shState, nil
	}
	dir := a.shieldDir()
	for _, d := range []string{dir, filepath.Join(dir, "staging")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, errf("shield_unavailable", "state dir: %v", err)
		}
	}
	q, err := shield.OpenQuarantine(filepath.Join(dir, "quarantine"))
	if err != nil {
		return nil, errf("shield_unavailable", "quarantine: %v", err)
	}
	active, all := shieldEngines(dir)
	sc := shield.NewScanner()
	sc.Engines = active
	sc.Allowlist = q.Allow
	st := &shieldState{dir: dir, scanner: sc, all: all, q: q, rtState: "off", rtWhy: "real-time watcher not started"}
	q.AccountRoot = func(acct string) (string, error) {
		e, err := a.home(acct)
		if err != nil {
			return "", err
		}
		return e.home, nil
	}
	q.Rescan = func(ctx context.Context, p, acct string) (shield.Result, error) { return sc.ScanAccount(ctx, p, acct) }
	st.seq = lastJournalSeq(filepath.Join(dir, "journal.jsonl"))
	a.shState = st
	return st, nil
}

// ---- journal --------------------------------------------------------------------

func lastJournalSeq(p string) int64 {
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()
	var last int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var ev rpc.ShieldEvent
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Seq > last {
			last = ev.Seq
		}
	}
	return last
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// journal appends ev (Seq, UID, TS filled in) and returns it.
func (st *shieldState) journal(ev rpc.ShieldEvent) rpc.ShieldEvent {
	st.jmu.Lock()
	defer st.jmu.Unlock()
	st.seq++
	ev.Seq = st.seq
	if ev.UID == "" {
		ev.UID = randHex(12)
	}
	if ev.TS == 0 {
		ev.TS = time.Now().Unix()
	}
	b, _ := json.Marshal(ev)
	f, err := os.OpenFile(filepath.Join(st.dir, "journal.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	return ev
}

func (a *Agent) shieldEvents(ctx context.Context, p rpc.ShieldEventsReq) (rpc.ShieldEventsResult, error) {
	res := rpc.ShieldEventsResult{Events: []rpc.ShieldEvent{}}
	st, err := a.sh()
	if err != nil {
		return res, err
	}
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	st.jmu.Lock()
	res.LastSeq = st.seq
	st.jmu.Unlock()
	f, err := os.Open(filepath.Join(st.dir, "journal.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return res, nil
	} else if err != nil {
		return res, errf("shield_journal", "%v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() && len(res.Events) < limit {
		var ev rpc.ShieldEvent
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Seq > p.Since {
			res.Events = append(res.Events, ev)
		}
	}
	return res, nil
}

// ---- paths ------------------------------------------------------------------------

// shieldPath canonicalises p (relative to or absolute inside the home) and
// refuses anything that resolves outside the account home.
func (a *Agent) shieldPath(user, p string) (string, error) {
	e, err := a.home(user)
	if err != nil {
		return "", err
	}
	if p == "" || strings.ContainsRune(p, 0) || len(p) > 4096 {
		return "", errf("invalid_path", "path")
	}
	home, err := filepath.EvalSymlinks(e.home)
	if err != nil {
		return "", errf("home_unavailable", "%s", user)
	}
	full := p
	if !filepath.IsAbs(p) {
		full = filepath.Join(e.home, p)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(full))
	if err != nil {
		return "", errf("not_found", "path")
	}
	if real != home && !strings.HasPrefix(real, home+string(filepath.Separator)) {
		return "", errf("path_outside_home", "path")
	}
	return real, nil
}

var stageIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func (a *Agent) stagePath(st *shieldState, user, id string) (string, error) {
	if !stageIDRe.MatchString(id) {
		return "", errf("invalid_stage_id", "id")
	}
	if _, err := a.home(user); err != nil {
		return "", err
	}
	d := filepath.Join(st.dir, "staging", user)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", errf("shield_unavailable", "staging: %v", err)
	}
	return filepath.Join(d, id), nil
}

// ---- scan ---------------------------------------------------------------------------

func (st *shieldState) eventFor(kind, source, user, path string, r shield.Result) rpc.ShieldEvent {
	return rpc.ShieldEvent{Kind: kind, Source: source, Account: user, Path: path, SHA256: r.SHA256, Outcome: string(r.Outcome),
		Action: string(r.Decision.Action), Reason: r.Decision.Reason, Detections: r.Detections}
}

// act applies a decision to a file already inside a home (on-demand and
// real-time scans): infected/quarantine => quarantine; everything else is
// recorded only (a file already on disk is not deleted by a heuristic).
func (st *shieldState) act(user, path, source string, r shield.Result) (rpc.ShieldEvent, string) {
	ev := st.eventFor("scan", source, user, path, r)
	var qid string
	if r.Decision.Action == shield.ActQuarantine {
		m, err := st.q.Put(path, user, r.Detections)
		if err != nil {
			ev.Reason += "; quarantine failed: " + err.Error()
			ev.Action = "record"
		} else {
			qid = m.ID
			ev.QuarantineID = qid
		}
	} else if r.Decision.Action != shield.ActAllow {
		ev.Action = "record"
	}
	return ev, qid
}

func (a *Agent) shieldScan(ctx context.Context, p rpc.ShieldScanReq) (rpc.ShieldScanResult, error) {
	var res rpc.ShieldScanResult
	st, err := a.sh()
	if err != nil {
		return res, err
	}
	full, err := a.shieldPath(p.User, p.Path)
	if err != nil {
		return res, err
	}
	fi, err := os.Lstat(full)
	if err != nil || !fi.Mode().IsRegular() {
		return res, errf("not_a_file", "only regular files can be scanned")
	}
	r, err := st.scanner.ScanAccount(ctx, full, p.User)
	if err != nil {
		return res, errf("scan_failed", "%v", err)
	}
	res.Result = r
	if r.Decision.Record || r.Outcome != shield.OutClean {
		ev, qid := st.act(p.User, full, "on_demand", r)
		ev = st.journal(ev)
		res.QuarantineID, res.EventSeq = qid, ev.Seq
	}
	a.Log.Info("audit", "action", "shield.scan", "user", p.User, "outcome", r.Outcome)
	return res, nil
}

// ---- quarantine -------------------------------------------------------------------

func (a *Agent) shieldQList(ctx context.Context, p rpc.ShieldQListReq) (rpc.ShieldQListResult, error) {
	res := rpc.ShieldQListResult{Items: []shield.QuarantineMeta{}}
	st, err := a.sh()
	if err != nil {
		return res, err
	}
	items, err := st.q.List(p.User)
	if err != nil {
		return res, errf("quarantine_failed", "%v", err)
	}
	if items != nil {
		res.Items = items
	}
	return res, nil
}

func (a *Agent) qItem(p rpc.ShieldQRef) (*shieldState, shield.QuarantineMeta, error) {
	st, err := a.sh()
	if err != nil {
		return nil, shield.QuarantineMeta{}, err
	}
	m, err := st.q.Get(p.ID)
	if err != nil || m.Account != p.User {
		return nil, m, errf("not_found", "quarantine item")
	}
	return st, m, nil
}

func (a *Agent) shieldQRestore(ctx context.Context, p rpc.ShieldQRef) (shield.QuarantineMeta, error) {
	st, m, err := a.qItem(p)
	if err != nil {
		return m, err
	}
	if m, err = st.q.Restore(ctx, p.ID); err != nil {
		return m, errf("restore_refused", "%v", err)
	}
	st.journal(rpc.ShieldEvent{Kind: "restore", Source: "admin", Account: p.User, Path: m.OrigPath, SHA256: m.SHA256, QuarantineID: p.ID, Action: "restore"})
	a.Log.Info("audit", "action", "shield.quarantine.restore", "user", p.User, "id", p.ID)
	return m, nil
}

func (a *Agent) shieldQDelete(ctx context.Context, p rpc.ShieldQRef) (shield.QuarantineMeta, error) {
	st, m, err := a.qItem(p)
	if err != nil {
		return m, err
	}
	if err := st.q.Delete(p.ID); err != nil {
		return m, errf("quarantine_failed", "%v", err)
	}
	st.journal(rpc.ShieldEvent{Kind: "delete", Source: "admin", Account: p.User, Path: m.OrigPath, SHA256: m.SHA256, QuarantineID: p.ID, Action: "delete"})
	a.Log.Info("audit", "action", "shield.quarantine.delete", "user", p.User, "id", p.ID)
	return m, nil
}

// shieldQFP adds the item's sha256 to the allowlist (account or global) and
// restores it (the rescan is then clean because of the allowlist).
func (a *Agent) shieldQFP(ctx context.Context, p rpc.ShieldQRef) (shield.QuarantineMeta, error) {
	st, m, err := a.qItem(p)
	if err != nil {
		return m, err
	}
	scope := p.Scope
	if scope == "" {
		scope = "account"
	}
	if scope != "account" && scope != "global" {
		return m, errf("invalid_scope", "scope: account|global")
	}
	if m, err = st.q.MarkFalsePositive(p.ID, scope); err != nil {
		return m, errf("quarantine_failed", "%v", err)
	}
	restored := "restored"
	if _, rerr := st.q.Restore(ctx, p.ID); rerr != nil {
		restored = "restore refused: " + rerr.Error()
	}
	st.journal(rpc.ShieldEvent{Kind: "falsepositive", Source: "admin", Account: p.User, Path: m.OrigPath, SHA256: m.SHA256,
		QuarantineID: p.ID, Action: "false_positive_" + scope, Reason: restored})
	a.Log.Info("audit", "action", "shield.quarantine.falsepositive", "user", p.User, "id", p.ID, "scope", scope)
	return m, nil
}

// ---- status ------------------------------------------------------------------------

func (a *Agent) shieldStatus(ctx context.Context, _ struct{}) (rpc.ShieldStatusResult, error) {
	var res rpc.ShieldStatusResult
	st, err := a.sh()
	if err != nil {
		return res, err
	}
	active := map[string]bool{}
	for _, e := range st.scanner.Engines {
		active[e.Name()] = true
	}
	for _, e := range st.all {
		ps := e.Status(ctx)
		ps.RealTime = active[e.Name()] && ps.Status == shield.StatusOK
		ps.OnDemand = active[e.Name()]
		res.Engines = append(res.Engines, ps)
	}
	res.Version = st.scanner.Version(ctx)
	res.Fanotify, res.FanReason = shield.FanotifyAvailable()
	a.shMu.Lock()
	res.Realtime, res.Reason = st.rtState, st.rtWhy
	if st.watcher != nil {
		c := st.watcher.Coverage()
		res.Coverage = &c
		if c.Degraded {
			res.Realtime, res.Reason = "degraded", strings.Join(c.Reasons, "; ")
		}
	}
	if st.queue != nil {
		qs := st.queue.Stats()
		res.Queue = &qs
	}
	a.shMu.Unlock()
	if items, err := st.q.List(""); err == nil {
		res.Quarantine = len(items)
	}
	st.jmu.Lock()
	res.LastSeq = st.seq
	st.jmu.Unlock()
	return res, nil
}

// ---- upload staging --------------------------------------------------------------

func (a *Agent) shieldStageChunk(ctx context.Context, p rpc.ShieldStageChunk) (struct{}, error) {
	st, err := a.sh()
	if err != nil {
		return struct{}{}, err
	}
	sp, err := a.stagePath(st, p.User, p.ID)
	if err != nil {
		return struct{}{}, err
	}
	b, err := base64.StdEncoding.DecodeString(p.Content)
	if err != nil || len(b) > fileops.MaxChunkBytes {
		return struct{}{}, errf("bad_chunk", "content")
	}
	if p.Offset < 0 || p.Offset+int64(len(b)) > fileops.MaxUploadBytes {
		return struct{}{}, errf("file_too_large", "upload")
	}
	flags := os.O_WRONLY | os.O_CREATE
	if p.Offset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(sp, flags|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return struct{}{}, errf("stage_failed", "open")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() != p.Offset { // chunks must be contiguous
		return struct{}{}, errf("bad_offset", "offset")
	}
	if _, err := f.WriteAt(b, p.Offset); err != nil {
		return struct{}{}, errf("stage_failed", "write")
	}
	return struct{}{}, nil
}

func (a *Agent) shieldStageAbort(ctx context.Context, p rpc.ShieldStageRef) (struct{}, error) {
	st, err := a.sh()
	if err != nil {
		return struct{}{}, err
	}
	sp, err := a.stagePath(st, p.User, p.ID)
	if err != nil {
		return struct{}{}, err
	}
	if err := os.Remove(sp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return struct{}{}, errf("stage_failed", "remove")
	}
	return struct{}{}, nil
}

func (a *Agent) shieldStageCommit(ctx context.Context, p rpc.ShieldStageCommit) (rpc.ShieldStageCommitResult, error) {
	var res rpc.ShieldStageCommitResult
	st, err := a.sh()
	if err != nil {
		return res, err
	}
	sp, err := a.stagePath(st, p.User, p.ID)
	if err != nil {
		return res, err
	}
	defer os.Remove(sp) // staging never outlives the commit
	if p.Path == "" || filepath.IsAbs(p.Path) || strings.ContainsRune(p.Path, 0) {
		return res, errf("invalid_path", "path")
	}
	if fi, err := os.Lstat(sp); err != nil || !fi.Mode().IsRegular() {
		return res, errf("not_found", "staged upload")
	}
	name := p.Name
	if name == "" {
		name = filepath.Base(p.Path)
	}
	r, err := st.scanner.ScanNamed(shield.WithAccount(ctx, p.User), sp, name)
	if err != nil {
		// no verdict at all: treat as scanner_unavailable (fail closed for scripts)
		r.Outcome = shield.OutUnavailable
		r.Errors = append(r.Errors, err.Error())
		if r.Type.Class == "" {
			r.Type.Class = shield.ClassOther
			if shield.IsScriptName(name) {
				r.Type.Class = shield.ClassScript
			}
		}
	}
	d := shield.Decide(r.Outcome, r.Type.Class, p.Policy)
	r.Decision = d
	e, _ := a.home(p.User)
	target := filepath.Join(e.home, filepath.Clean("/"+p.Path)) // logical target (journal/restore)
	res = rpc.ShieldStageCommitResult{Action: string(d.Action), Reason: d.Reason, Outcome: string(r.Outcome), Class: string(r.Type.Class),
		SHA256: r.SHA256, Detections: r.Detections}
	switch d.Action {
	case shield.ActAllow, shield.ActAllowWarning:
		if err := shieldPlace(a, ctx, p.User, sp, p.Path); err != nil {
			return res, err
		}
		res.Placed = true
	case shield.ActQuarantine, shield.ActHold:
		m, qerr := st.q.PutAs(sp, target, p.User, r.Detections)
		if qerr != nil {
			res.Action, res.Reason = string(shield.ActBlock), d.Reason+"; quarantine failed, upload discarded"
		} else {
			res.QuarantineID = m.ID
		}
	default: // block
	}
	if d.Record || r.Outcome != shield.OutClean {
		ev := st.journal(rpc.ShieldEvent{Kind: "upload", Source: "upload", Account: p.User, Path: target, SHA256: r.SHA256,
			Outcome: res.Outcome, Action: res.Action, Reason: res.Reason, Detections: r.Detections, QuarantineID: res.QuarantineID})
		res.EventUID = ev.UID
	}
	a.Log.Info("audit", "action", "shield.stage.commit", "user", p.User, "outcome", res.Outcome, "decision", res.Action)
	return res, nil
}

// placeViaHelper copies the root-owned staged file into the home through the
// files helper (running as the account), then renames it into place.
func placeViaHelper(a *Agent, ctx context.Context, user, staged, rel string) error {
	f, err := os.Open(staged)
	if err != nil {
		return errf("stage_failed", "open")
	}
	defer f.Close()
	tmp := filepath.Join(filepath.Dir(rel), ".bpanel-upload-"+randHex(6))
	buf := make([]byte, fileops.MaxChunkBytes/2)
	var off int64
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 || off == 0 {
			op := rpc.FileOp{User: user, Op: "write_chunk", Path: tmp, Offset: off, Content: base64.StdEncoding.EncodeToString(buf[:n])}
			if _, err := a.files(ctx, op); err != nil {
				_, _ = a.files(ctx, rpc.FileOp{User: user, Op: "delete", Path: tmp})
				return err
			}
			off += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
				break
			}
			_, _ = a.files(ctx, rpc.FileOp{User: user, Op: "delete", Path: tmp})
			return errf("stage_failed", "read")
		}
	}
	if _, err := a.files(ctx, rpc.FileOp{User: user, Op: "rename", Path: tmp, Dest: rel}); err != nil {
		_, _ = a.files(ctx, rpc.FileOp{User: user, Op: "delete", Path: tmp})
		return err
	}
	return nil
}

// ---- real-time watcher -------------------------------------------------------------

// StartShield starts the real-time watcher + scan queue over HomeBase unless
// shield_realtime is false. inotify limits => status "degraded" with the
// reason; no inotify => "unsupported". Never fatal for the agent.
func (a *Agent) StartShield(ctx context.Context) {
	st, err := a.sh()
	if err != nil {
		a.Log.Warn("shield unavailable", "err", err)
		return
	}
	a.shMu.Lock()
	defer a.shMu.Unlock()
	if a.Cfg.ShieldRealtime != nil && !*a.Cfg.ShieldRealtime {
		st.rtState, st.rtWhy = "off", "disabled in the agent configuration (shield_realtime=false)"
		return
	}
	q, err := shield.NewQueue(shield.QueueConfig{Workers: 2, Debounce: 2 * time.Second, StatePath: filepath.Join(st.dir, "queue.json")},
		func(ctx context.Context, it shield.QueueItem) error {
			if _, err := a.home(it.Account); err != nil {
				return nil // not a managed account: ignore
			}
			fi, err := os.Lstat(it.Path)
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			r, err := st.scanner.ScanAccount(ctx, it.Path, it.Account)
			if err != nil {
				return err
			}
			if r.Decision.Record || r.Outcome != shield.OutClean {
				ev, _ := st.act(it.Account, it.Path, "realtime", r)
				ev.Kind = "realtime"
				st.journal(ev)
			}
			return nil
		})
	if err != nil {
		st.rtState, st.rtWhy = "unsupported", "queue: "+err.Error()
		return
	}
	base := a.Cfg.HomeBase
	acct := func(p string) string {
		rel, err := filepath.Rel(base, p)
		if err != nil || strings.HasPrefix(rel, "..") {
			return ""
		}
		return strings.SplitN(rel, string(filepath.Separator), 2)[0]
	}
	beh := shield.NewBehavior(shield.DefaultBehaviorConfig())
	onAlert := func(al shield.Alert) {
		st.journal(rpc.ShieldEvent{Kind: "behavior", Source: "behavior", Account: al.Account, Path: al.Path, Outcome: "suspicious",
			Action: "record", Reason: al.Detail, Detections: []shield.Detection{{Engine: "bpanel-behavior", Signature: al.Rule,
				Verdict: shield.Suspicious, Severity: al.Severity, Detail: al.Detail}}})
	}
	w, err := shield.NewWatcher([]string{base}, acct, shield.FeedWatcher(q, beh, onAlert))
	if err != nil {
		st.rtState, st.rtWhy = "unsupported", err.Error()
		return
	}
	q.Start()
	st.queue, st.watcher = q, w
	st.rtState, st.rtWhy = "on", "inotify watcher over "+base
	go func() {
		<-ctx.Done()
		_ = w.Close()
		_ = q.Stop()
	}()
}
