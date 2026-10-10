package agent

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// ---- R2-WB-1: every tenant action requires a panel-managed account ------------
//
// Only password/suspend/quota/terminate used to check the ownership marker;
// every other action took any Linux account with a uid in 1000..59999 and a
// home below /home - the cloud image's sudo user (ubuntu, uid 1000) or the
// operator's own login. A compromised API could then render a vhost and a
// PHP pool running as that user, install a crontab for it, read its files or
// back them up.
//
// Dispatch now checks, before any handler runs, that the account named by
// the request is managed (panel ownership marker or bpanel-users group),
// for every method in accountField. A method is either listed there or
// explicitly in gateExempt; TestR2WB1EveryMethodClassified fails when a new
// method is added to neither.

// accountField maps a tenant method to the JSON key naming its account.
// optional: an empty value is allowed (server-level use, e.g. the panel
// hostname certificate); a non-empty value is still checked.
var accountField = map[string]struct {
	key      string
	optional bool
}{
	rpc.MAccountSuspend: {"user", false}, rpc.MAccountPassword: {"user", false}, rpc.MAccountQuota: {"user", false},
	rpc.MVhostApply: {"user", false}, rpc.MVhostRemove: {"owner", false},
	rpc.MPHPPoolApply: {"user", false}, rpc.MPHPPoolRemove: {"user", false},
	rpc.MDBCreate: {"owner", false}, rpc.MDBDrop: {"owner", false}, rpc.MDBUserCreate: {"owner", false},
	rpc.MDBUserDrop: {"owner", false}, rpc.MDBUserPassword: {"owner", false}, rpc.MDBGrant: {"owner", false},
	rpc.MDBRevoke: {"owner", false}, rpc.MDBSizes: {"prefix", false},
	rpc.MDNSZoneCreate: {"owner", false}, rpc.MDNSZoneDelete: {"owner", false}, rpc.MDNSZoneGet: {"owner", false},
	rpc.MDNSRRSetReplace: {"owner", false}, rpc.MDNSRRSetDelete: {"owner", false},
	rpc.MMailDomainOn: {"user", false}, rpc.MMailDomainOff: {"user", false},
	rpc.MMailboxCreate: {"user", false}, rpc.MMailboxDelete: {"user", false}, rpc.MMailboxPassword: {"user", false},
	rpc.MMailboxQuota: {"user", false}, rpc.MMailForwardSet: {"owner", false}, rpc.MMailForwardDel: {"owner", false},
	rpc.MMailUsage: {"user", false},
	rpc.MFTPCreate: {"user", false}, rpc.MFTPDelete: {"owner", false}, rpc.MFTPPassword: {"user", false},
	rpc.MCronSet:  {"user", false},
	rpc.MSSLIssue: {"user", true}, rpc.MSSLSelfSigned: {"user", true}, rpc.MSSLInfo: {"owner", true},
	rpc.MLogTail: {"user", false}, rpc.MDiskUsage: {"user", false}, rpc.MFiles: {"user", false},
	rpc.MBackupRun: {"user", false}, rpc.MBackupList: {"user", false}, rpc.MBackupRestore: {"user", false},
	rpc.MBackupVerify: {"user", false}, rpc.MBackupDelete: {"user", false}, // v0.4 backup_verify.go
	rpc.MBackupCredsExport: {"user", false}, rpc.MBackupCredsLoad: {"user", false}, rpc.MBackupForget: {"user", false}, // v0.4 backup_creds.go
	rpc.MDBXRemoteSync: {"owner", false}, rpc.MDBXProcessList: {"owner", false}, rpc.MDBXKill: {"owner", false}, // v0.4 dbx.go
	rpc.MPGCreate: {"owner", false}, rpc.MPGDrop: {"owner", false}, rpc.MPGPassword: {"owner", false}, rpc.MPGLimit: {"owner", false}, rpc.MPGSizes: {"owner", false}, // v0.4 pg.go
	rpc.MXferRestoreHome: {"user", false}, rpc.MXferRestoreDB: {"owner", false}, rpc.MXferExport: {"user", false}, // v0.4 xfer.go
}

// gateExempt are the methods that name no tenant account (server-level) or
// do their own, stricter account handling.
var gateExempt = map[string]string{
	rpc.MPing: "server", rpc.MSysInfo: "server", rpc.MServiceStatus: "server", rpc.MServiceAction: "server (allowlist)",
	rpc.MPHPVersions: "server", rpc.MPHPInstall: "server", rpc.MMailRootAlias: "server",
	rpc.MAccountCreate:     "creates the account (refuses existing non-managed users)",
	rpc.MAccountExists:     "read-only existence probe",
	rpc.MAccountTerminate:  "own not_managed check (homeAny + isManaged)",
	rpc.MAccountQuotaBatch: "checks every item with managedHome",
	rpc.MProvidersDetect:   "server (read-only component inventory, no parameters)",
	rpc.MXferList:          "server (admin xfer directory)", rpc.MXferAnalyse: "server (read-only parse of an archive in the xfer directory)", rpc.MXferFetch: "server (download into the xfer directory, SSRF-guarded)", rpc.MXferDelete: "server (xfer directory)", // v0.4 xfer.go
	rpc.MPGStatus: "server (PostgreSQL presence/version, no parameters)", // v0.4 pg.go
}

// gate enforces accountField for one request.
func (a *Agent) gate(method string, raw json.RawMessage) error {
	f, ok := accountField[method]
	if !ok {
		if _, ex := gateExempt[method]; ex || a.testExempt[method] {
			return nil
		}
		return errf("unknown_method", "%s", method) // unclassified: refuse
	}
	var m map[string]json.RawMessage
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &m); err != nil {
			return &rpc.Error{Code: "bad_params", Message: err.Error()}
		}
	}
	var name string
	if v, ok := m[f.key]; ok {
		if err := json.Unmarshal(v, &name); err != nil {
			return &rpc.Error{Code: "bad_params", Message: f.key + ": " + err.Error()}
		}
	}
	if name == "" {
		if f.optional {
			return nil
		}
		return errf("owner_required", "%s: no account given (%s)", method, f.key)
	}
	_, err := a.managedHome(name)
	return err
}

// ---- R2-WB-7: strict parameter decoding ----------------------------------------

// strictKeys refuses keys that only match a struct field case-insensitively
// ("USER" next to "user": the last one silently won) and duplicate keys.
func strictKeys(raw json.RawMessage, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	known := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" {
			tag = t.Field(i).Name
		}
		if tag != "-" {
			known[tag] = true
		}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil // not an object: the typed decode reports it
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := kt.(string)
		if !known[k] {
			return fmt.Errorf("unknown field %q", k)
		}
		if seen[k] {
			return fmt.Errorf("duplicate field %q", k)
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}
