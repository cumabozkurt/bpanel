// SPDX-License-Identifier: Apache-2.0

package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/xfer"
)

// xferFakeDir is the fake agent's xfer directory ("" = xfer methods unhandled).
var xferFakeDir string

// fakeXfer answers xfer.* like the agent, using the real parser.
func fakeXfer(method string, b []byte) (any, bool, error) {
	if !strings.HasPrefix(method, "xfer.") || xferFakeDir == "" {
		return nil, false, nil
	}
	switch method {
	case rpc.MXferList:
		return rpc.XferArchiveList{Archives: []rpc.XferArchive{}, Dir: xferFakeDir}, true, nil
	case rpc.MXferAnalyse:
		var p rpc.XferArchiveRef
		_ = json.Unmarshal(b, &p)
		m, err := xfer.Analyse(filepath.Join(xferFakeDir, filepath.Base(p.Archive)), xfer.DefaultLimits)
		if err != nil {
			var xe *xfer.Error
			code := "action_failed"
			if e, ok := err.(*xfer.Error); ok {
				xe = e
				code = xe.Code.Error()
			}
			return nil, true, &rpc.Error{Code: code, Message: "analyse"}
		}
		return rpc.XferAnalyseResult{Model: *m}, true, nil
	case rpc.MXferRestoreHome:
		return rpc.XferRestoreResult{Files: 1, Bytes: 10}, true, nil
	case rpc.MXferRestoreDB:
		var p rpc.XferRestoreDB
		_ = json.Unmarshal(b, &p)
		if !strings.HasPrefix(p.DB, p.Owner+"_") {
			return nil, true, &rpc.Error{Code: "invalid_db_name"}
		}
		return rpc.XferRestoreResult{Files: 1, Bytes: 25}, true, nil
	case rpc.MXferExport:
		var p rpc.XferExport
		_ = json.Unmarshal(b, &p)
		var man xfer.Manifest
		_ = json.Unmarshal(p.Manifest, &man)
		f, _ := os.Create(filepath.Join(xferFakeDir, p.Archive))
		gz := gzip.NewWriter(f)
		w := xfer.NewWriter(gz)
		_ = w.AddBytes("homedir/public_html/index.html", []byte("hi"))
		for _, d := range p.Databases {
			_ = w.AddBytes("mysql/"+d+".sql", []byte("CREATE TABLE t(i int);"))
		}
		for _, bl := range p.Blobs {
			_ = w.AddBytes(bl.Name, []byte(bl.Content))
		}
		err := w.Close(man)
		gz.Close()
		f.Close()
		if err != nil {
			return nil, true, err
		}
		return rpc.XferExportResult{Archive: p.Archive, Files: 1 + len(p.Databases) + len(p.Blobs)}, true, nil
	case rpc.MXferDelete:
		return rpc.Empty{}, true, nil
	}
	return nil, false, nil
}

func writeCpmove(t *testing.T, dir, user, domain string) string {
	t.Helper()
	r := "cpmove-" + user + "/"
	files := []struct{ n, b string }{
		{r + "cp/" + user, "USER=" + user + "\nDNS=" + domain + "\nCONTACTEMAIL=owner@example.org\n"},
		{r + "userdata/main", "---\naddon_domains: {}\nmain_domain: " + domain + "\nparked_domains:\n  - parked-" + domain + "\nsub_domains:\n  - blog." + domain + "\n"},
		{r + "homedir/public_html/index.html", "<h1>synthetic</h1>"},
		{r + "mysql/" + user + "_wp.sql", "CREATE TABLE t (id int);\n"},
		{r + "dnszones/" + domain + ".db", "$TTL 300\nwww 300 IN A 192.0.2.10\n"},
		{r + "va/" + domain, "info@" + domain + ": someone@example.org\n"},
		{r + "etc/" + domain + "/passwd", "info:x:1000:1000::/home/" + user + "/mail/" + domain + "/info:/home/" + user + "\n"},
		{r + "cron/" + user, "* * * * * true\n"},
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		tw.WriteHeader(&tar.Header{Name: f.n, Mode: 0o644, Size: int64(len(f.b)), Typeflag: tar.TypeReg})
		tw.Write([]byte(f.b))
	}
	tw.Close()
	gz.Close()
	name := "cpmove-" + user + ".tar.gz"
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestXferAnalyseImportExport(t *testing.T) {
	xferFakeDir = t.TempDir()
	t.Cleanup(func() { xferFakeDir = "" })
	e := newEnv(t)
	as := mustLoginAdmin(t, e)
	archive := writeCpmove(t, xferFakeDir, "carol", "carol.test")

	code, m := as.call("POST", "/api/v1/admin/xfer/analyse", map[string]any{"archive": archive})
	if code != 200 {
		t.Fatalf("analyse %d %v", code, m)
	}
	model := m["model"].(map[string]any)
	if model["format"] != "cpanel" || len(m["conflicts"].([]any)) != 0 || len(model["unsupported"].([]any)) != 1 {
		t.Fatalf("analyse: %v", m)
	}
	if code, m := as.call("POST", "/api/v1/admin/xfer/analyse", map[string]any{"archive": "../etc/passwd.tar.gz"}); code != 400 || m["error"] != "xfer_invalid_archive" {
		t.Fatalf("bad name: %d %v", code, m)
	}

	// conflict: username / domain already exist
	e.tenant("dave", "dave.test")
	dup := writeCpmove(t, xferFakeDir, "dave", "dave.test")
	_, m = as.call("POST", "/api/v1/admin/xfer/analyse", map[string]any{"archive": dup})
	if c := m["conflicts"].([]any); len(c) < 2 {
		t.Fatalf("conflicts: %v", m["conflicts"])
	}

	code, m = as.call("POST", "/api/v1/admin/xfer/import", map[string]any{"archive": archive})
	if code != 200 {
		t.Fatalf("import %d %v", code, m)
	}
	for e.srv.Jobs().RunOnce(context.Background()) {
	}
	var status, report string
	if err := e.srv.Store.DB.QueryRow(`SELECT status, report FROM xfer_runs WHERE job_id=?`, m["job_id"]).Scan(&status, &report); err != nil {
		t.Fatal(err)
	}
	if status != "done" {
		t.Fatalf("status %s: %s", status, report)
	}
	var rep XferReport
	json.Unmarshal([]byte(report), &rep)
	got := map[string]string{}
	for _, s := range rep.Steps {
		got[s.Part+":"+s.Item] = s.Status
	}
	for k, want := range map[string]string{"account:carol": "action_required", "domain:parked-carol.test": "ok", "domain:blog.carol.test": "ok",
		"dns:carol.test": "ok", "home:": "ok", "database:carol_wp": "action_required", "mailbox:info@carol.test": "action_required",
		"forwarder:info@carol.test → someone@example.org": "ok"} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q (report %s)", k, got[k], want, report)
		}
	}
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM domains d JOIN users u ON u.id=d.user_id WHERE u.username='carol'`).Scan(&n)
	if n != 3 {
		t.Fatalf("domains created: %d", n)
	}
	// importing the conflicting archive fails without creating anything
	_, m = as.call("POST", "/api/v1/admin/xfer/import", map[string]any{"archive": dup})
	for e.srv.Jobs().RunOnce(context.Background()) {
	}
	e.srv.Store.DB.QueryRow(`SELECT status FROM xfer_runs WHERE job_id=?`, m["job_id"]).Scan(&status)
	if status != "failed" {
		t.Fatalf("conflicting import: %s", status)
	}

	// export carol -> BPanel archive -> analyse: round trip of the import model
	var uid int64
	e.srv.Store.DB.QueryRow(`SELECT id FROM users WHERE username='carol'`).Scan(&uid)
	code, m = as.call("POST", "/api/v1/admin/accounts/"+strconv.FormatInt(uid, 10)+"/export", nil)
	if code != 200 {
		t.Fatalf("export %d %v", code, m)
	}
	for e.srv.Jobs().RunOnce(context.Background()) {
	}
	mod, err := xfer.Analyse(filepath.Join(xferFakeDir, m["archive"].(string)), xfer.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if mod.Format != "bpanel" || mod.Account.Username != "carol" || mod.Account.MainDomain != "carol.test" || len(mod.Domains) != 3 ||
		len(mod.Databases) != 1 || len(mod.Mailboxes) != 1 || len(mod.Forwarders) != 1 {
		t.Fatalf("round trip model: %+v", mod)
	}
	code, m = as.call("GET", "/api/v1/admin/xfer/imports", nil)
	if code != 200 || len(m["runs"].([]any)) != 3 {
		t.Fatalf("history %d %v", code, m)
	}
}

func TestXferFetchGuardAndPerms(t *testing.T) {
	xferFakeDir = t.TempDir()
	t.Cleanup(func() { xferFakeDir = "" })
	e := newEnv(t)
	as := mustLoginAdmin(t, e)
	for _, c := range []struct {
		body map[string]any
		code string
	}{
		{map[string]any{"host": "127.0.0.1", "user": "root", "remote_path": "/a.tar.gz", "auth": "key", "secret": "k"}, "xfer_remote_blocked"},
		{map[string]any{"host": "169.254.169.254", "user": "root", "remote_path": "/a.tar.gz", "auth": "key", "secret": "k"}, "xfer_remote_blocked"},
		{map[string]any{"host": "h.example", "user": "root", "remote_path": "/a.tar.gz;id", "auth": "key", "secret": "k"}, "xfer_remote_invalid"},
		{map[string]any{"host": "h.example", "user": "root", "remote_path": "/a.tar.gz", "auth": "key", "secret": ""}, "xfer_remote_invalid"},
	} {
		if code, m := as.call("POST", "/api/v1/admin/xfer/fetch", c.body); code != 400 || m["error"] != c.code {
			t.Errorf("%v: %d %v", c.body, code, m)
		}
	}
	e.tenant("erin", "erin.test")
	us := mustLogin(t, e, e.user, "erin", "")
	if code, _ := us.call("GET", "/api/v1/admin/xfer/archives", nil); code == 200 {
		t.Fatal("tenant reached the Transfer Tool")
	}
}
