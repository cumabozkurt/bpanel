// Package agent is the root-privileged half of BPANEL. It listens only on a
// unix socket, accepts connections only from the bpanel API uid
// (SO_PEERCRED), and executes a fixed set of typed actions. No action
// accepts a shell string; external programs are run with argv.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

// Config is read from /etc/bpanel/agent.json.
type Config struct {
	Socket          string   `json:"socket"`
	AllowedUIDs     []int    `json:"allowed_uids"`
	HomeBase        string   `json:"home_base"`
	PDNSURL         string   `json:"pdns_url"`
	PDNSKey         string   `json:"pdns_key"`
	BackupRepo      string   `json:"backup_repo"`                 // default local restic repo base dir
	BackupCredsFile string   `json:"backup_creds_file,omitempty"` // v0.4 legacy target creds (0600 root JSON), migrated into the secret store
	ResticBin       string   `json:"restic_bin"`
	ACMEDir         string   `json:"acme_dir"`
	SSLDir          string   `json:"ssl_dir"`
	ACMEEmail       string   `json:"acme_email"`
	ACMEStaging     bool     `json:"acme_staging"`
	Hostname        string   `json:"hostname"`
	NoSystemd       bool     `json:"no_systemd"` // test mode: skip reloads, keep config tests
	Profile         string   `json:"profile"`
	ExtraUnits      []string `json:"extra_units"`
	AccountsDir     string   `json:"accounts_dir"` // root-owned ownership markers of panel-created accounts
	RestoreDir      string   `json:"restore_dir"`  // root-owned staging area for restic restores
	OwnersDir       string   `json:"owners_dir"`   // root-owned domain/zone/mail-domain ownership registry (CODE-27)
	ResticPassDir   string   `json:"restic_pass_dir"`
	// DovecotSyntax is "2.3" or "2.4"; empty = read /etc/bpanel/capabilities.json,
	// then ask `dovecot --version` (R2-E2E-3 handoff).
	DovecotSyntax  string `json:"dovecot_syntax,omitempty"`
	NetsecDir      string `json:"netsec_dir,omitempty"`      // v0.4 firewall state (pending change, snapshots); default /var/lib/bpanel/netsec
	ShieldDir      string `json:"shield_dir,omitempty"`      // v0.4 Shield state (quarantine, journal, staging); default /var/lib/bpanel/shield
	ShieldRealtime *bool  `json:"shield_realtime,omitempty"` // v0.4 Shield real-time watcher; default on
	RemoteListen   string `json:"remote_listen,omitempty"`   // v0.4 msrv: opt-in mTLS listener, e.g. ":8445"; empty = unix socket only
	RemoteDir      string `json:"remote_dir,omitempty"`      // v0.4 msrv: node.key/node.crt/ca.crt/revoked.json; default /etc/bpanel/node
}

func DefaultConfig() Config {
	return Config{Socket: "/run/bpanel/agent.sock", HomeBase: "/home", PDNSURL: "http://127.0.0.1:8081",
		BackupRepo: "/var/backups/bpanel", ResticBin: "/usr/local/lib/bpanel/bin/restic", ACMEDir: "/etc/bpanel/acme",
		SSLDir: "/etc/bpanel/ssl", Profile: "full", AccountsDir: "/etc/bpanel/accounts", RestoreDir: "/var/lib/bpanel/restore",
		ResticPassDir: "/etc/bpanel/restic", OwnersDir: "/etc/bpanel/owners"}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if os.Getenv("BPANEL_NO_SYSTEMD") == "1" {
		c.NoSystemd = true
	}
	return c, nil
}

type Agent struct {
	// configTestFn replaces the real config test (tests only).
	configTestFn func(ctx context.Context, unit string) error
	// runtime directories (variables for tests)
	domlogDir, acmeDir, resticCache string
	http2Once                       sync.Once
	http2                           bool
	http2Probe                      func() bool // tests
	Cfg                             Config
	L                               *distro.Layout
	Log                             *slog.Logger
	locks                           sync.Map // per-subsystem mutexes
	routes                          map[string]handler
	semOnce                         sync.Once
	conns, bigLines                 chan struct{}   // R2-WB-6
	testExempt                      map[string]bool // tests only: extra gate-exempt methods
	dovecotOnce                     sync.Once
	dovecot24                       bool
	shMu                            sync.Mutex   // v0.4 shield (shield.go)
	shState                         *shieldState // lazily created
}

// Agent memory bounds (R2-WB-6): requests up to smallLine bytes are read
// freely (every action except file chunks); a longer line needs one of
// bigLineSlots slots, so at most maxConns*smallLine + bigLineSlots*MaxLine
// bytes of request data are buffered at any time (~100 MiB, not unbounded).
const (
	maxConns     = 64
	smallLine    = 1 << 20
	bigLineSlots = 2
)

func (a *Agent) initSems() {
	a.semOnce.Do(func() {
		a.conns = make(chan struct{}, maxConns)
		a.bigLines = make(chan struct{}, bigLineSlots)
	})
}

func (a *Agent) connSem() chan struct{} { a.initSems(); return a.conns }

// readRequest reads one request line under the memory budget.
func (a *Agent) readRequest(br *bufio.Reader) ([]byte, error) {
	a.initSems()
	var out []byte
	big := false
	defer func() {
		if big {
			<-a.bigLines
		}
	}()
	for {
		chunk, err := br.ReadSlice('\n')
		if len(out)+len(chunk) > smallLine && !big {
			t := time.NewTimer(30 * time.Second)
			select {
			case a.bigLines <- struct{}{}:
				big = true
				t.Stop()
			case <-t.C:
				return nil, errors.New("request too large for the current load")
			}
		}
		out = append(out, chunk...)
		if len(out) > rpc.MaxLine {
			return nil, errors.New("request too large")
		}
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
	}
}

type handler func(ctx context.Context, raw json.RawMessage) (any, error)

func New(cfg Config, l *distro.Layout, log *slog.Logger) *Agent {
	a := &Agent{Cfg: cfg, L: l, Log: log, domlogDir: "/var/log/bpanel/domlogs", acmeDir: acmeWebroot,
		resticCache: "/var/cache/bpanel/restic-cache"}
	a.routes = a.register()
	mergeRoutes(a.routes, a.isolationRoutes()) // v0.4 isolation
	mergeRoutes(a.routes, a.netsecRoutes())    // v0.4 netsec firewall
	mergeRoutes(a.routes, a.msrvRoutes())      // v0.4 msrv (msrv_remote.go)
	mergeRoutes(a.routes, a.shieldRoutes())    // v0.4 shield
	mergeRoutes(a.routes, a.mailxRoutes())     // v0.4 mailx (mailx.go)
	mergeRoutes(a.routes, a.updatesRoutes())   // v0.4 adminx update preferences
	mergeRoutes(a.routes, a.usagexRoutes())    // v0.4 usagex (bandwidth, fail2ban)
	mergeRoutes(a.routes, a.v11UserRoutes())   // v1.1 parity: stats, leech, routing, DAV, GnuPG, SSH keys
	mergeRoutes(a.routes, a.v11ServerRoutes()) // v1.1 parity: mail queue, troubleshooter, hostname, IPs, PHP extensions
	mergeRoutes(a.routes, a.devxRoutes())      // v0.4 devx (git, terminal, traceroute)
	mergeRoutes(a.routes, a.webxRoutes())      // v0.4 webx (web extras include)
	mergeRoutes(a.routes, a.appxRoutes())      // v0.4 appx (applications, installer, WordPress)
	mergeRoutes(a.routes, a.dnsxRoutes())      // v0.4 dnsx (dnsx.go)
	mergeRoutes(a.routes, a.obsxRoutes())      // v0.4 obsx (obsx.go)
	mergeRoutes(a.routes, a.clusterxRoutes())  // v0.4 clusterx (DNS cluster, plugins)
	a.netsecRecover()                          // roll back a change left pending by a previous process
	return a
}

// lock serialises changes to one subsystem (e.g. "nginx", "postfix").
func (a *Agent) lock(name string) func() {
	m, _ := a.locks.LoadOrStore(name, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// bind adapts a typed function to the generic handler signature.
func bind[P any, R any](f func(context.Context, P) (R, error)) handler {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p P
		dec := json.NewDecoder(bytesReader(raw))
		dec.DisallowUnknownFields()
		if len(raw) > 0 {
			// R2-WB-7: exact (case-sensitive) keys, no duplicates, no trailing data
			if err := strictKeys(raw, reflect.TypeOf(p)); err != nil {
				return nil, &rpc.Error{Code: "bad_params", Message: err.Error()}
			}
			if err := dec.Decode(&p); err != nil {
				return nil, &rpc.Error{Code: "bad_params", Message: err.Error()}
			}
			if _, err := dec.Token(); !errors.Is(err, io.EOF) {
				return nil, &rpc.Error{Code: "bad_params", Message: "trailing data after the parameters"}
			}
		}
		return f(ctx, p)
	}
}

func (a *Agent) register() map[string]handler {
	return map[string]handler{
		rpc.MPing:              bind(a.ping),
		rpc.MSysInfo:           bind(a.sysInfo),
		rpc.MAccountCreate:     bind(a.accountCreate),
		rpc.MAccountExists:     bind(a.accountExists),
		rpc.MAccountSuspend:    bind(a.accountSuspend),
		rpc.MAccountTerminate:  bind(a.accountTerminate),
		rpc.MAccountPassword:   bind(a.accountPassword),
		rpc.MAccountQuota:      bind(a.accountQuota),
		rpc.MAccountQuotaBatch: bind(a.accountQuotaBatch),
		rpc.MVhostApply:        bind(a.vhostApply),
		rpc.MVhostRemove:       bind(a.vhostRemove),
		rpc.MPHPPoolApply:      bind(a.phpPoolApply),
		rpc.MPHPPoolRemove:     bind(a.phpPoolRemove),
		rpc.MPHPVersions:       bind(a.phpVersions),
		rpc.MPHPInstall:        bind(a.phpInstall),
		rpc.MDBCreate:          bind(a.dbCreate),
		rpc.MDBDrop:            bind(a.dbDrop),
		rpc.MDBUserCreate:      bind(a.dbUserCreate),
		rpc.MDBUserDrop:        bind(a.dbUserDrop),
		rpc.MDBUserPassword:    bind(a.dbUserPassword),
		rpc.MDBGrant:           bind(a.dbGrant),
		rpc.MDBRevoke:          bind(a.dbRevoke),
		rpc.MDBSizes:           bind(a.dbSizes),
		rpc.MMailRootAlias:     bind(a.mailRootAlias),
		rpc.MDNSZoneCreate:     bind(a.dnsZoneCreate),
		rpc.MDNSZoneDelete:     bind(a.dnsZoneDelete),
		rpc.MDNSZoneGet:        bind(a.dnsZoneGet),
		rpc.MDNSRRSetReplace:   bind(a.dnsRRSetReplace),
		rpc.MDNSRRSetDelete:    bind(a.dnsRRSetDelete),
		rpc.MMailDomainOn:      bind(a.mailDomainEnable),
		rpc.MMailDomainOff:     bind(a.mailDomainDisable),
		rpc.MMailboxCreate:     bind(a.mailboxCreate),
		rpc.MMailboxDelete:     bind(a.mailboxDelete),
		rpc.MMailboxPassword:   bind(a.mailboxPassword),
		rpc.MMailboxQuota:      bind(a.mailboxQuota),
		rpc.MMailForwardSet:    bind(a.mailForwardSet),
		rpc.MMailForwardDel:    bind(a.mailForwardDelete),
		rpc.MMailUsage:         bind(a.mailUsage),
		rpc.MFTPCreate:         bind(a.ftpCreate),
		rpc.MFTPDelete:         bind(a.ftpDelete),
		rpc.MFTPPassword:       bind(a.ftpPassword),
		rpc.MCronSet:           bind(a.cronSet),
		rpc.MSSLIssue:          bind(a.sslIssue),
		rpc.MSSLSelfSigned:     bind(a.sslSelfSigned),
		rpc.MSSLInfo:           bind(a.sslInfo),
		rpc.MServiceStatus:     bind(a.serviceStatus),
		rpc.MServiceAction:     bind(a.serviceAction),
		rpc.MLogTail:           bind(a.logTail),
		rpc.MDiskUsage:         bind(a.diskUsage),
		rpc.MFiles:             bind(a.files),
		rpc.MBackupRun:         bind(a.backupRun),
		rpc.MBackupList:        bind(a.backupList),
		rpc.MBackupRestore:     bind(a.backupRestore),
		rpc.MBackupVerify:      bind(a.backupVerify),                                                                              // v0.4 backup_verify.go
		rpc.MDBXRemoteSync:     bind(a.dbxRemoteSync), rpc.MDBXProcessList: bind(a.dbxProcessList), rpc.MDBXKill: bind(a.dbxKill), // v0.4 dbx.go
		rpc.MPGStatus: bind(a.pgStatus), rpc.MPGCreate: bind(a.pgCreate), rpc.MPGDrop: bind(a.pgDrop), rpc.MPGPassword: bind(a.pgPassword), rpc.MPGLimit: bind(a.pgLimit), rpc.MPGSizes: bind(a.pgSizes), // v0.4 pg.go
		rpc.MBackupDelete:      bind(a.backupDelete),
		rpc.MBackupCredsExport: bind(a.backupCredsExport), // v0.4 backup_creds.go
		rpc.MBackupCredsLoad:   bind(a.backupCredsLoad),
		rpc.MBackupForget:      bind(a.backupForget),
		rpc.MProvidersDetect:   bind(a.providersDetect),                                                                                                                                                                                                                                        // v0.4 inventory
		rpc.MXferList:          bind(a.xferList), rpc.MXferAnalyse: bind(a.xferAnalyse), rpc.MXferFetch: bind(a.xferFetch), rpc.MXferDelete: bind(a.xferDelete), rpc.MXferRestoreHome: bind(a.xferRestoreHome), rpc.MXferRestoreDB: bind(a.xferRestoreDB), rpc.MXferExport: bind(a.xferExport), // v0.4 xfer.go
	}
}

// Methods returns the whitelist (used by tests and docs).
func (a *Agent) Methods() []string {
	out := make([]string, 0, len(a.routes))
	for k := range a.routes {
		out = append(out, k)
	}
	return out
}

// Dispatch runs one request in-process (used by the server and tests).
func (a *Agent) Dispatch(ctx context.Context, req rpc.Request) rpc.Response {
	resp := rpc.Response{ID: req.ID}
	h, ok := a.routes[req.Method]
	if !ok || req.V != rpc.Version {
		resp.Error = &rpc.Error{Code: "unknown_method", Message: req.Method}
		return resp
	}
	start := time.Now()
	if err := a.gate(req.Method, req.Params); err != nil { // R2-WB-1
		var re *rpc.Error
		if !errors.As(err, &re) {
			re = &rpc.Error{Code: "action_failed", Message: err.Error()}
		}
		resp.Error = re
		a.Log.Warn("action refused", "method", req.Method, "code", re.Code, "err", re.Message)
		return resp
	}
	res, err := h(ctx, req.Params)
	if err != nil {
		var re *rpc.Error
		if !errors.As(err, &re) {
			re = &rpc.Error{Code: "action_failed", Message: err.Error()}
		}
		resp.Error = re
		a.Log.Warn("action failed", "method", req.Method, "err", re.Message, "ms", time.Since(start).Milliseconds())
		return resp
	}
	a.Log.Info("action ok", "method", req.Method, "ms", time.Since(start).Milliseconds())
	b, err := json.Marshal(res)
	if err != nil {
		resp.Error = &rpc.Error{Code: "action_failed", Message: "encode result: " + err.Error()}
		return resp
	}
	resp.Result = b
	return resp
}

// Serve listens on the configured unix socket until ctx is cancelled.
func (a *Agent) Serve(ctx context.Context) error {
	sock := a.Cfg.Socket
	if err := os.MkdirAll(filepath.Dir(sock), 0o750); err != nil {
		return err
	}
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	// The directory is group-owned by bpanel; the socket itself is 0660.
	if err := os.Chmod(sock, 0o660); err != nil {
		return err
	}
	if len(a.Cfg.AllowedUIDs) > 0 && os.Geteuid() == 0 {
		if err := os.Chown(sock, 0, groupOfUID(a.Cfg.AllowedUIDs[0])); err != nil {
			return err
		}
	}
	go func() { <-ctx.Done(); _ = ln.Close() }()
	go a.MigrateHomes()   // R2-E2E-10
	go a.UnlockRepos(ctx) // R2-PERF-14
	go a.StartShield(ctx) // v0.4 shield real-time watcher (shield.go)
	a.Log.Info("agent listening", "socket", sock, "distro", a.L.Pretty)
	backoff := 5 * time.Millisecond
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// e.g. EMFILE: back off instead of spinning (CODE-14)
			a.Log.Warn("accept", "err", err)
			time.Sleep(backoff)
			backoff = min(backoff*2, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		// R2-WB-6: at most maxConns connections at once; a flood waits in
		// the kernel backlog instead of growing the agent's memory
		select {
		case a.connSem() <- struct{}{}:
		case <-ctx.Done():
			c.Close()
			return nil
		}
		go func() {
			defer func() { <-a.connSem() }()
			a.handleConn(ctx, c.(*net.UnixConn))
		}()
	}
}

// handleConn serves exactly one request per connection (that is what the
// client sends). The action's context is cancelled when the API closes the
// connection (it gave up or its own context ended), so the agent never keeps
// working on an action the API is already rolling back (CODE-14).
func (a *Agent) handleConn(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil || !a.allowed(uid) {
		a.Log.Warn("rejected peer", "uid", uid, "err", err)
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReaderSize(c, 64<<10)
	line, err := a.readRequest(br)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			a.writeResp(c, rpc.Response{Error: &rpc.Error{Code: "bad_request", Message: err.Error()}})
		}
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req rpc.Request
	if err := json.Unmarshal(line, &req); err != nil {
		a.writeResp(c, rpc.Response{Error: &rpc.Error{Code: "bad_request", Message: err.Error()}})
		return
	}
	cctx, cancel := context.WithTimeout(ctx, rpc.MethodTimeout(req.Method))
	defer cancel()
	go func() {
		// The client sends nothing after its request: any read result means
		// the peer closed (or broke) the connection.
		var b [1]byte
		_, _ = br.Read(b[:])
		cancel()
	}()
	resp := a.Dispatch(cctx, req)
	if cctx.Err() != nil && ctx.Err() == nil && resp.Error == nil {
		a.Log.Warn("action finished after the client went away", "method", req.Method)
	}
	a.writeResp(c, resp)
}

func (a *Agent) writeResp(c net.Conn, resp rpc.Response) {
	b, err := json.Marshal(resp)
	if err != nil {
		b, _ = json.Marshal(rpc.Response{ID: resp.ID, Error: &rpc.Error{Code: "action_failed", Message: "encode response"}}) //nolint:errchkjson
	}
	b = append(b, '\n')
	_ = c.SetWriteDeadline(time.Now().Add(time.Minute))
	if _, err := c.Write(b); err != nil {
		a.Log.Warn("write response", "err", err)
	}
}

// readLine reads one '\n'-terminated line of at most max bytes.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > max {
			return nil, errors.New("request too large")
		}
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
	}
}

func (a *Agent) allowed(uid int) bool {
	if uid == 0 {
		return true
	}
	for _, u := range a.Cfg.AllowedUIDs {
		if u == uid {
			return true
		}
	}
	return false
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return -1, err
	}
	if cerr != nil {
		return -1, cerr
	}
	return int(cred.Uid), nil
}

func groupOfUID(uid int) int {
	// Best effort: look up the primary gid in /etc/passwd.
	if u, err := lookupUID(uid); err == nil {
		return u.gid
	}
	return 0
}

func (a *Agent) ping(ctx context.Context, _ rpc.Empty) (rpc.PingResult, error) {
	h, err := os.Hostname()
	if err != nil {
		h = ""
	}
	return rpc.PingResult{Version: Version, Distro: a.L.Pretty, Hostname: h}, nil
}

// Version is set by main via ldflags.
var Version = "1.2.1"

func errf(code, format string, args ...any) error {
	return &rpc.Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
