//go:build dev

// Package mockagent is an in-process stand-in for bpanel-agent used by
// `bpanel-api --dev`. It keeps state in memory, runs the real File Manager
// code against a sandbox directory, and never touches the system.
package mockagent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/fileops"
	"github.com/cumabozkurt/bpanel/internal/sysinfo"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

type Mock struct {
	Base     string // sandbox dir holding fake homes
	mu       sync.Mutex
	zones    map[string][]rpc.DNSRecord
	services map[string]rpc.ServiceState
	php      map[string]bool
	snaps    map[string][]rpc.BackupSnapshot
	Calls    []string
}

func New(base string) *Mock {
	m := &Mock{Base: base, zones: map[string][]rpc.DNSRecord{}, snaps: map[string][]rpc.BackupSnapshot{},
		php: map[string]bool{"8.2": true, "8.3": true, "8.4": true}}
	now := time.Now().Add(-49 * time.Hour).Unix()
	m.services = map[string]rpc.ServiceState{}
	for _, s := range [][2]string{{"nginx", "Nginx"}, {"apache2", "Apache"}, {"mariadb", "MariaDB"}, {"pdns", "PowerDNS"},
		{"postfix", "Postfix"}, {"dovecot", "Dovecot"}, {"rspamd", "Rspamd"}, {"redis-server", "Redis"}, {"pure-ftpd", "Pure-FTPd"},
		{"ssh", "OpenSSH"}, {"cron", "Cron"}, {"bpanel-api", "BPANEL API"}, {"php8.2-fpm", "PHP 8.2 FPM"},
		{"php8.3-fpm", "PHP 8.3 FPM"}, {"php8.4-fpm", "PHP 8.4 FPM"}} {
		m.services[s[0]] = rpc.ServiceState{Unit: s[0], Name: s[1], Active: "active", Sub: "running", Enabled: "enabled",
			MemoryBytes: uint64(20+len(s[0])*7) << 20, SinceUnix: now}
	}
	os.MkdirAll(base, 0o755)
	return m
}

func conv(in any, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func (m *Mock) home(user string) string { return filepath.Join(m.Base, user) }

func (m *Mock) Call(ctx context.Context, method string, params any, result any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, method)
	var out any = rpc.Empty{}
	switch method {
	case rpc.MPing:
		out = rpc.PingResult{Version: "0.1.0-dev", Distro: "Ubuntu 24.04 LTS (mock agent)", Hostname: "server.example.com"}
	case rpc.MSysInfo:
		s := sysinfo.Collect()
		s.Hostname = "server.example.com"
		s.OS = "Ubuntu 24.04.3 LTS (mock agent)"
		out = s
	case rpc.MProvidersDetect:
		// a typical single-server install; commercial scanners absent
		out = rpc.ProvidersDetectResult{Distro: "Ubuntu 24.04 LTS (mock agent)", Family: "debian", Systemd: true, Probes: []rpc.ProviderProbe{
			{Component: "apache", Binary: "/usr/sbin/apache2"},
			{Component: "dovecot", Present: true, Binary: "/usr/sbin/dovecot", Version: "2.3.21", Unit: "dovecot", UnitState: "active", Configured: true},
			{Component: "fail2ban", Present: true, Binary: "/usr/bin/fail2ban-client", Version: "1.0.2", Unit: "fail2ban", UnitState: "active", Configured: true},
			{Component: "imunify360"},
			{Component: "lego", Present: true, Binary: "embedded", Version: "4.21.0", Configured: true},
			{Component: "mariadb", Present: true, Binary: "/usr/sbin/mariadbd", Version: "10.11.8", Unit: "mariadb", UnitState: "active", Configured: true},
			{Component: "monarx"},
			{Component: "nginx", Present: true, Binary: "/usr/sbin/nginx", Version: "1.24.0", Unit: "nginx", UnitState: "active", Configured: true},
			{Component: "php-fpm", Present: true, Binary: "/usr/sbin/php-fpm8.3", Version: "8.3.6", Unit: "php8.3-fpm", UnitState: "active", Configured: true},
			{Component: "postfix", Present: true, Binary: "/usr/sbin/postconf", Version: "3.8.6", Unit: "postfix", UnitState: "active", Configured: true},
			{Component: "powerdns", Present: true, Binary: "/usr/sbin/pdns_server", Version: "4.8.3", Unit: "pdns", UnitState: "active", Configured: true},
			{Component: "restic", Present: true, Binary: "/usr/local/lib/bpanel/bin/restic", Version: "0.17.3"},
			{Component: "rspamd", Present: true, Binary: "/usr/bin/rspamd", Version: "3.8.1", Unit: "rspamd", UnitState: "inactive", Configured: true},
		}}
	case rpc.MAccountCreate:
		var p rpc.AccountCreate
		conv(params, &p)
		if err := validate.Username(p.User); err != nil {
			return &rpc.Error{Code: err.Error(), Message: p.User}
		}
		h := m.home(p.User)
		for _, d := range []string{"public_html", "logs", "tmp", "mail", "etc", "backups", ".bpanel"} {
			os.MkdirAll(filepath.Join(h, d), 0o755)
		}
		idx := filepath.Join(h, "public_html", "index.html")
		if _, err := os.Stat(idx); err != nil {
			os.WriteFile(idx, []byte("<!doctype html><h1>"+p.User+"</h1>\n"), 0o644)
		}
		out = rpc.AccountCreateResult{UID: 1000 + len(p.User)*13, GID: 1000 + len(p.User)*13, Home: "/home/" + p.User, Created: true}
	case rpc.MAccountQuotaBatch:
		out = rpc.AccountQuotaBatchResult{Failed: map[string]string{}}
	case rpc.MAccountExists:
		// the sandbox has no /etc/passwd of its own: nothing pre-exists
		out = rpc.AccountExistsResult{}
	case rpc.MAccountTerminate:
		var p rpc.AccountRef
		conv(params, &p)
		if validate.Username(p.User) == nil {
			os.RemoveAll(m.home(p.User))
		}
	case rpc.MAccountSuspend, rpc.MAccountPassword, rpc.MAccountQuota, rpc.MVhostApply, rpc.MVhostRemove,
		rpc.MPHPPoolApply, rpc.MPHPPoolRemove, rpc.MDBCreate, rpc.MDBDrop, rpc.MDBUserCreate, rpc.MDBUserDrop,
		rpc.MDBUserPassword, rpc.MDBGrant, rpc.MDBRevoke, rpc.MMailDomainOff, rpc.MMailboxCreate, rpc.MMailboxDelete,
		rpc.MMailboxPassword, rpc.MMailboxQuota, rpc.MMailForwardSet, rpc.MMailForwardDel, rpc.MFTPCreate, rpc.MFTPDelete,
		rpc.MFTPPassword, rpc.MCronSet, rpc.MMailRootAlias:
		// accepted; state lives in the API database
		if method == rpc.MDBGrant {
			var p rpc.DBGrant
			conv(params, &p)
			if len(p.Privileges) == 0 { // same contract as the real agent (handoff-ui H-4)
				return &rpc.Error{Code: "invalid_privilege", Message: "no privileges given"}
			}
		}
	case rpc.MPHPVersions:
		var r rpc.PHPVersionsResult
		for _, v := range []string{"8.1", "8.2", "8.3", "8.4", "8.5"} {
			r.Versions = append(r.Versions, rpc.PHPVersion{Version: v, Installed: m.php[v], Running: m.php[v], Default: v == "8.3",
				Unit: "php" + v + "-fpm", Binary: "/usr/sbin/php-fpm" + v})
		}
		out = r
	case rpc.MPHPInstall:
		var p rpc.PHPInstall
		conv(params, &p)
		m.php[p.Version] = !p.Remove
		unit := "php" + p.Version + "-fpm"
		if p.Remove {
			delete(m.services, unit)
		} else {
			m.services[unit] = rpc.ServiceState{Unit: unit, Name: "PHP " + p.Version + " FPM", Active: "active", Sub: "running", Enabled: "enabled", MemoryBytes: 18 << 20, SinceUnix: time.Now().Unix()}
		}
	case rpc.MDBSizes:
		var p rpc.DBSizesReq
		conv(params, &p)
		out = rpc.DBSizes{Sizes: map[string]int64{}}
	case rpc.MDNSZoneCreate:
		var p rpc.DNSZone
		conv(params, &p)
		m.zones[p.Zone] = append([]rpc.DNSRecord{{Name: p.Zone, Type: "SOA", TTL: 3600,
			Content: "ns1." + p.Zone + ". hostmaster." + p.Zone + ". " + time.Now().Format("2006010201") + " 10800 3600 604800 3600"}}, p.Records...)
	case rpc.MDNSZoneDelete:
		var p rpc.ZoneRef
		conv(params, &p)
		delete(m.zones, p.Zone)
	case rpc.MDNSZoneGet:
		var p rpc.ZoneRef
		conv(params, &p)
		recs, ok := m.zones[p.Zone]
		if !ok {
			return &rpc.Error{Code: "pdns_error", Message: "zone not found"}
		}
		out = rpc.DNSZone{Zone: p.Zone, Records: recs, Serial: time.Now().Unix()}
	case rpc.MDNSRRSetReplace:
		var p rpc.RRSet
		conv(params, &p)
		recs := m.zones[p.Zone]
		var keep []rpc.DNSRecord
		for _, r := range recs {
			if !(r.Name == p.Name && r.Type == p.Type) {
				keep = append(keep, r)
			}
		}
		for _, c := range p.Records {
			keep = append(keep, rpc.DNSRecord{Name: p.Name, Type: p.Type, TTL: p.TTL, Content: c})
		}
		m.zones[p.Zone] = keep
	case rpc.MDNSRRSetDelete:
		var p rpc.RRSetRef
		conv(params, &p)
		var keep []rpc.DNSRecord
		for _, r := range m.zones[p.Zone] {
			if !(r.Name == p.Name && r.Type == p.Type) {
				keep = append(keep, r)
			}
		}
		m.zones[p.Zone] = keep
	case rpc.MMailDomainOn:
		b := make([]byte, 270)
		rand.Read(b)
		out = rpc.MailDomainResult{DKIMSelector: "bpanel", DKIMRecord: "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(b)}
	case rpc.MMailUsage:
		var p rpc.MailUsageReq
		conv(params, &p)
		out = rpc.MailUsage{Bytes: map[string]int64{}}
	case rpc.MSSLIssue, rpc.MSSLSelfSigned, rpc.MSSLInfo:
		var p rpc.SSLIssue
		conv(params, &p)
		out = rpc.SSLInfo{Domain: p.Domain, Present: true, Issuer: "(mock) Let's Encrypt R11",
			NotAfter: time.Now().AddDate(0, 0, 89).UTC().Format(time.RFC3339), SANs: append([]string{p.Domain}, p.SANs...)}
	case rpc.MServiceStatus:
		var r rpc.ServiceStatus
		for _, s := range m.services {
			r.Services = append(r.Services, s)
		}
		sort.Slice(r.Services, func(i, j int) bool { return r.Services[i].Unit < r.Services[j].Unit })
		out = r
	case rpc.MServiceAction:
		var p rpc.ServiceAction
		conv(params, &p)
		s, ok := m.services[p.Unit]
		if !ok {
			return &rpc.Error{Code: "unit_not_allowed", Message: p.Unit}
		}
		switch p.Action {
		case "stop":
			s.Active, s.Sub = "inactive", "dead"
		default:
			s.Active, s.Sub, s.SinceUnix = "active", "running", time.Now().Unix()
		}
		m.services[p.Unit] = s
	case rpc.MLogTail:
		var p rpc.LogTail
		conv(params, &p)
		var lines []string
		t := time.Now()
		for i := 0; i < 25; i++ {
			ts := t.Add(-time.Duration(i*97) * time.Second)
			if p.Kind == "error" {
				lines = append(lines, fmt.Sprintf("%s [error] 1234#1234: *%d open() \"/home/demo/public_html/favicon.ico\" failed (2: No such file or directory), client: 203.0.113.%d, server: %s",
					ts.Format("2006/01/02 15:04:05"), 900+i, 10+i, p.Domain))
			} else {
				lines = append(lines, fmt.Sprintf("198.51.100.%d - - [%s] \"GET /%s HTTP/2.0\" %d %d \"-\" \"Mozilla/5.0\"",
					20+i, ts.Format("02/Jan/2006:15:04:05 -0700"), []string{"", "wp-login.php", "about", "contact", "blog/hello-world"}[i%5],
					[]int{200, 200, 404, 200, 301}[i%5], 1024+i*37))
			}
		}
		out = rpc.LogLines{Lines: lines}
	case rpc.MDiskUsage:
		var p rpc.DiskUsageReq
		conv(params, &p)
		var du rpc.DiskUsage
		root := m.home(p.User)
		ents, _ := os.ReadDir(root)
		for _, e := range ents {
			var sz int64
			filepath.Walk(filepath.Join(root, e.Name()), func(_ string, info os.FileInfo, err error) error {
				if err == nil {
					sz += info.Size()
					du.Inodes++
				}
				return nil
			})
			du.Entries = append(du.Entries, rpc.DiskEntry{Path: e.Name(), Bytes: sz})
			du.TotalBytes += sz
		}
		sort.Slice(du.Entries, func(i, j int) bool { return du.Entries[i].Bytes > du.Entries[j].Bytes })
		out = du
	case rpc.MFiles:
		var p rpc.FileOp
		conv(params, &p)
		if validate.Username(p.User) != nil {
			return &rpc.Error{Code: "invalid_username"}
		}
		os.MkdirAll(m.home(p.User), 0o755)
		root, err := os.OpenRoot(m.home(p.User))
		if err != nil {
			return err
		}
		defer root.Close()
		r, err := fileops.Exec(root, p)
		if err != nil {
			return &rpc.Error{Code: err.Error(), Message: p.Path}
		}
		out = r
	case rpc.MBackupRun:
		var p rpc.BackupRun
		conv(params, &p)
		b := make([]byte, 32)
		rand.Read(b)
		id := fmt.Sprintf("%x", b)
		tags := []string{"files"}
		m.snaps[p.User] = append([]rpc.BackupSnapshot{{ID: id, ShortID: id[:8], Time: time.Now().UTC().Format(time.RFC3339),
			Paths: []string{"/home/" + p.User}, Tags: tags}}, m.snaps[p.User]...)
		for _, db := range p.Databases {
			rand.Read(b)
			did := fmt.Sprintf("%x", b)
			m.snaps[p.User] = append([]rpc.BackupSnapshot{{ID: did, ShortID: did[:8], Time: time.Now().UTC().Format(time.RFC3339),
				Paths: []string{"/" + db + ".sql"}, Tags: []string{"db", db}}}, m.snaps[p.User]...)
		}
		out = rpc.BackupRunResult{SnapshotIDs: []string{id}}
	case rpc.MBackupList:
		var p rpc.AccountRef
		conv(params, &p)
		out = rpc.BackupList{Snapshots: m.snaps[p.User]}
	case rpc.MBackupRestore:
		var p rpc.BackupRestore
		conv(params, &p)
		if strings.HasPrefix(p.Path, "db:") {
			out = rpc.BackupRestoreResult{RestoredTo: "database " + strings.TrimPrefix(p.Path, "db:")}
		} else {
			out = rpc.BackupRestoreResult{RestoredTo: "/home/" + p.User + "/backups/restore-" + time.Now().Format("20060102-150405")}
		}
	case rpc.MBackupVerify:
		var p rpc.BackupVerify
		conv(params, &p)
		v := rpc.BackupVerification{User: p.User, Status: "no_snapshot", Error: "no files snapshot", Started: time.Now().UTC().Format(time.RFC3339), Finished: time.Now().UTC().Format(time.RFC3339)}
		for _, s := range m.snaps[p.User] {
			if len(s.Tags) > 0 && s.Tags[0] == "files" {
				v = rpc.BackupVerification{User: p.User, SnapshotID: s.ID, Status: "ok", FilesChecked: 3, CheckOK: true, Started: v.Started, Finished: v.Finished}
				break
			}
		}
		out = v
	case rpc.MBackupDelete:
		var p rpc.BackupDelete
		conv(params, &p)
		keep := m.snaps[p.User][:0]
		for _, s := range m.snaps[p.User] {
			if s.ID != p.Snapshot {
				keep = append(keep, s)
			}
		}
		m.snaps[p.User] = keep
		out = struct{}{}
	case rpc.MBackupCredsExport, rpc.MBackupCredsLoad, rpc.MBackupForget: // v0.4 backup_creds.go
		r, err := mockBackupCreds(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MMailSieveApply, rpc.MMailSpamApply, rpc.MMailLogSearch: // v0.4 mailx.go
		r, err := mockMailx(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MIsolationApply, rpc.MIsolationStatus, rpc.MIsolationStats:
		out = mockIsolation(method, params)
	case rpc.MUpdatesStatus, rpc.MUpdatesApply: // v0.4 adminx.go
		out = mockUpdates(method, params)
	case rpc.MShieldStageChunk, rpc.MShieldStageCommit, rpc.MShieldStageAbort, rpc.MShieldStatus, rpc.MShieldQList, rpc.MShieldEvents,
		rpc.MShieldScan, rpc.MShieldQRestore, rpc.MShieldQDelete, rpc.MShieldQFP:
		r, err := m.mockShield(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MObsxFIMScan, rpc.MObsxOSHealth: // v0.4 obsx.go
		out = m.mockObsx(method)
	case rpc.MDNSSEC, rpc.MListApply, rpc.MListSubs: // v0.4 dnsx.go
		r, err := m.mockDnsx(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MTraceRoute, rpc.MTermOpen, rpc.MTermWrite, rpc.MTermRead, rpc.MTermResize, rpc.MTermClose, rpc.MGitClone, rpc.MGitInit, rpc.MGitInfo, rpc.MGitDeploy, rpc.MGitRemove: // v0.4 devx.go (restored by appx after an I/O error on mock.go)
		r, err := m.mockDevx(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MAppxRuntimes, rpc.MAppxAppApply, rpc.MAppxAppRemove, rpc.MAppxAppCtl, rpc.MAppxAppLogs, rpc.MAppxAppDeps,
		rpc.MAppxInstall, rpc.MAppxWP, rpc.MAppxWPCLIInstall: // v0.4 appx.go
		r, err := mockAppxCall(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MClusterApply, rpc.MPluginInstall, rpc.MPluginRemove: // v0.4 clusterx.go
		r, err := mockClusterx(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MWebxApply: // v0.4 webx.go
		r, err := mockWebx(params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MDBXRemoteSync, rpc.MDBXProcessList, rpc.MDBXKill, rpc.MPGStatus, rpc.MPGCreate, rpc.MPGDrop, rpc.MPGPassword, rpc.MPGLimit, rpc.MPGSizes: // v0.4 dbx
		r, err := m.mockDbx(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MXferList, rpc.MXferAnalyse, rpc.MXferDelete, rpc.MXferFetch, rpc.MXferRestoreHome, rpc.MXferRestoreDB, rpc.MXferExport: // v0.4 xfer
		r, err := m.mockXfer(method, params)
		if err != nil {
			return err
		}
		out = r
	case rpc.MUsageBandwidthScan, rpc.MF2BStatus, rpc.MF2BUnban, rpc.MF2BIgnore: // v0.4 usagex
		r, err := m.mockUsagex(method, params)
		if err != nil {
			return err
		}
		out = r
	default:
		return &rpc.Error{Code: "unknown_method", Message: method}
	}
	if result != nil {
		return conv(out, result)
	}
	return nil
}
