// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/xfer"
)

// v0.4 xfer (spec §10): account transfer archives. Everything here treats
// an archive strictly as data: names are canonicalised, links leaving the
// root, hard links and device nodes are refused (internal/xfer), homes are
// written through os.Root with the account's uid/gid, SQL dumps are loaded by
// the mysql client running as the account's Unix user with a temporary
// MariaDB login that only holds privileges on the target database.

// xferDir holds archives (root-owned 0700). Variable for tests.
var xferDir = "/var/lib/bpanel/xfer"

var xferNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(tar\.gz|tgz|tar)$`)

func xferPath(name string) (string, error) {
	if !xferNameRe.MatchString(name) || strings.Contains(name, "..") {
		return "", errf("xfer_invalid_archive", "invalid archive name")
	}
	p := filepath.Join(xferDir, name)
	fi, err := os.Lstat(p)
	if err != nil {
		return p, errf("xfer_archive_not_found", "archive not found")
	}
	if !fi.Mode().IsRegular() {
		return p, errf("xfer_invalid_archive", "archive is not a regular file")
	}
	return p, nil
}

func xferErr(err error) error {
	var xe *xfer.Error
	if errors.As(err, &xe) {
		return errf(xe.Code.Error(), "%s", xe.Detail)
	}
	if err == nil {
		return nil
	}
	var re *rpc.Error
	if errors.As(err, &re) {
		return err
	}
	return errf("action_failed", "%v", err)
}

func (a *Agent) xferList(ctx context.Context, _ rpc.Empty) (rpc.XferArchiveList, error) {
	out := rpc.XferArchiveList{Archives: []rpc.XferArchive{}, Dir: xferDir}
	ents, err := os.ReadDir(xferDir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, xferErr(err)
	}
	for _, e := range ents {
		if !e.Type().IsRegular() || !xferNameRe.MatchString(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			out.Archives = append(out.Archives, rpc.XferArchive{Name: e.Name(), Bytes: fi.Size(), ModTime: fi.ModTime().Unix()})
		}
	}
	sort.Slice(out.Archives, func(i, j int) bool { return out.Archives[i].ModTime > out.Archives[j].ModTime })
	return out, nil
}

func (a *Agent) xferAnalyse(ctx context.Context, p rpc.XferArchiveRef) (rpc.XferAnalyseResult, error) {
	ap, err := xferPath(p.Archive)
	if err != nil {
		return rpc.XferAnalyseResult{}, err
	}
	m, err := xfer.Analyse(ap, xfer.DefaultLimits)
	if err != nil {
		return rpc.XferAnalyseResult{}, xferErr(err)
	}
	res := rpc.XferAnalyseResult{Model: *m, MailHashes: map[string]string{}}
	for _, mb := range m.Mailboxes {
		if mb.Hash != "" {
			res.MailHashes[mb.Address] = mb.Hash
		}
	}
	return res, nil
}

func (a *Agent) xferDelete(ctx context.Context, p rpc.XferArchiveRef) (rpc.Empty, error) {
	ap, err := xferPath(p.Archive)
	if err != nil {
		return rpc.Empty{}, err
	}
	return rpc.Empty{}, xferErr(os.Remove(ap))
}

func xferRandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// xferFetch pulls an archive with scp -s (SFTP) argv; the key/password only
// ever lives in a 0600 file / the child's environment and is removed after.
func (a *Agent) xferFetch(ctx context.Context, p rpc.XferFetch) (rpc.XferFetchResult, error) {
	r := p.Remote
	if err := r.Validate(); err != nil {
		return rpc.XferFetchResult{}, xferErr(err)
	}
	if !xferNameRe.MatchString(p.Archive) || p.Secret == "" {
		return rpc.XferFetchResult{}, errf("xfer_remote_invalid", "archive name or credential missing")
	}
	if _, err := exec.LookPath("scp"); err != nil {
		return rpc.XferFetchResult{}, errf("not_installed", "scp (openssh-client) is not installed")
	}
	runner := []string{}
	if r.Auth == "password" {
		if _, err := exec.LookPath("sshpass"); err != nil {
			return rpc.XferFetchResult{}, errf("not_installed", "sshpass is not installed; use key authentication")
		}
		runner = []string{"sshpass", "-e"}
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ip, err := xfer.ResolveSafe(rctx, net.DefaultResolver, r.Host, p.AllowPrivate)
	cancel()
	if err != nil {
		return rpc.XferFetchResult{}, xferErr(err)
	}
	if err := os.MkdirAll(xferDir, 0o700); err != nil {
		return rpc.XferFetchResult{}, xferErr(err)
	}
	dest := filepath.Join(xferDir, p.Archive)
	if _, err := os.Lstat(dest); err == nil {
		return rpc.XferFetchResult{}, errf("already_exists", "archive exists")
	}
	tmp, err := os.MkdirTemp(xferDir, ".fetch-")
	if err != nil {
		return rpc.XferFetchResult{}, xferErr(err)
	}
	defer os.RemoveAll(tmp)
	key := filepath.Join(tmp, "id")
	if r.Auth == "key" {
		sec := p.Secret
		if !strings.HasSuffix(sec, "\n") {
			sec += "\n"
		}
		if err := os.WriteFile(key, []byte(sec), 0o600); err != nil {
			return rpc.XferFetchResult{}, xferErr(err)
		}
	}
	part := filepath.Join(tmp, "archive.part")
	argv := append(runner, xfer.ScpArgv(r, ip, key, filepath.Join(xferDir, ".known_hosts"), part, 20)...)
	cctx, ccancel := context.WithTimeout(ctx, 2*time.Hour)
	defer ccancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/root"}
	if r.Auth == "password" {
		cmd.Env = append(cmd.Env, "SSHPASS="+p.Secret)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(lastLines(string(out), 2))
		msg = strings.ReplaceAll(msg, p.Secret, "***")
		return rpc.XferFetchResult{}, errf("xfer_remote_failed", "scp: %v: %s", err, msg)
	}
	fi, err := os.Lstat(part)
	if err != nil || !fi.Mode().IsRegular() {
		return rpc.XferFetchResult{}, errf("xfer_remote_failed", "no archive received")
	}
	if p.MaxBytes > 0 && fi.Size() > p.MaxBytes {
		return rpc.XferFetchResult{}, errf("xfer_archive_too_large", "archive exceeds %d bytes", p.MaxBytes)
	}
	if err := os.Rename(part, dest); err != nil {
		return rpc.XferFetchResult{}, xferErr(err)
	}
	return rpc.XferFetchResult{Bytes: fi.Size()}, nil
}

func (a *Agent) xferRestoreHome(ctx context.Context, p rpc.XferRestoreHome) (rpc.XferRestoreResult, error) {
	ap, err := xferPath(p.Archive)
	if err != nil {
		return rpc.XferRestoreResult{}, err
	}
	e, err := lookupUser(p.User)
	if err != nil {
		return rpc.XferRestoreResult{}, err
	}
	pre, err := xfer.CleanName(p.Prefix)
	if err != nil || pre == "." || path.Base(pre) != "homedir" {
		return rpc.XferRestoreResult{}, errf("xfer_archive_unsafe", "invalid home prefix")
	}
	skip := func(rel string) bool { // never import SSH trust from another server
		return rel == ".ssh" || strings.HasPrefix(rel, ".ssh/")
	}
	n, b, err := xfer.Extract(ap, e.home, xfer.DefaultLimits, xfer.ExtractOptions{Prefix: pre, Skip: skip, UID: e.uid, GID: e.gid, Chown: os.Geteuid() == 0})
	if err != nil {
		return rpc.XferRestoreResult{Files: n, Bytes: b}, xferErr(err)
	}
	return rpc.XferRestoreResult{Files: n, Bytes: b}, nil
}

func mysqlClient(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// xferRestoreDB streams one dump into db through a temporary login limited
// to that database, as the account's Unix user.
func (a *Agent) xferRestoreDB(ctx context.Context, p rpc.XferRestoreDB) (rpc.XferRestoreResult, error) {
	if err := dbxOwner(p.Owner); err != nil {
		return rpc.XferRestoreResult{}, err
	}
	if err := checkOwned(p.Owner, p.DB, "invalid_db_name"); err != nil {
		return rpc.XferRestoreResult{}, err
	}
	member, err := xfer.CleanName(p.Member)
	if err != nil || !strings.HasSuffix(member, ".sql") || path.Base(path.Dir(member)) != "mysql" {
		return rpc.XferRestoreResult{}, errf("xfer_archive_unsafe", "invalid dump member")
	}
	ap, err := xferPath(p.Archive)
	if err != nil {
		return rpc.XferRestoreResult{}, err
	}
	e, err := lookupUser(p.Owner)
	if err != nil {
		return rpc.XferRestoreResult{}, err
	}
	bin := mysqlClient("mariadb", "mysql")
	if bin == "" {
		return rpc.XferRestoreResult{}, errf("not_installed", "MariaDB client is not installed")
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.XferRestoreResult{}, err
	}
	defer db.Close()
	tmpUser := p.Owner + "_x" + xferRandHex(3)
	pw := xferRandHex(18)
	if err := xferTempLogin(ctx, db, tmpUser, pw, p.DB); err != nil {
		return rpc.XferRestoreResult{}, err
	}
	defer func() {
		dctx, c := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_, _ = db.ExecContext(dctx, "DROP USER IF EXISTS ?@'localhost'", tmpUser)
		c()
	}()
	var res rpc.XferRestoreResult
	found := false
	err = xfer.WalkFile(ap, xfer.DefaultLimits, func(en xfer.Entry, body io.Reader) error {
		if en.Name != member || found {
			return nil
		}
		found = true
		cctx, cancel := context.WithTimeout(ctx, 4*time.Hour)
		defer cancel()
		cmd := userCmd(cctx, e, bin, "--no-defaults", "--user="+tmpUser, "--host=localhost", "--database="+p.DB,
			"--local-infile=0", "--binary-mode", "--force", "--default-character-set=utf8mb4")
		cmd.Env = append(cmd.Env, "MYSQL_PWD="+pw)
		cr := &countReader{r: body}
		cmd.Stdin = cr
		out, err := cmd.CombinedOutput()
		res.Bytes = cr.n
		res.Files = 1
		if err != nil {
			return errf("xfer_db_import_failed", "%s: %s", p.DB, strings.ReplaceAll(strings.TrimSpace(lastLines(string(out), 3)), pw, "***"))
		}
		return nil
	})
	if err != nil {
		return res, xferErr(err)
	}
	if !found {
		return res, errf("xfer_archive_not_found", "dump not in archive")
	}
	return res, nil
}

func xferTempLogin(ctx context.Context, db *sql.DB, user, pw, dbName string) error {
	if _, err := db.ExecContext(ctx, "CREATE USER ?@'localhost' IDENTIFIED BY ?", user, pw); err != nil {
		return errf("xfer_db_import_failed", "temporary login: %v", err)
	}
	q := "GRANT ALL PRIVILEGES ON `" + strings.ReplaceAll(dbName, "`", "``") + "`.* TO ?@'localhost'"
	if _, err := db.ExecContext(ctx, q, user); err != nil {
		_, _ = db.ExecContext(ctx, "DROP USER IF EXISTS ?@'localhost'", user)
		return errf("xfer_db_import_failed", "temporary grant: %v", err)
	}
	return nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

// xferExport writes <archive> = homedir/ + mysql/<db>.sql + blobs + manifest.
func (a *Agent) xferExport(ctx context.Context, p rpc.XferExport) (rpc.XferExportResult, error) {
	if !xferNameRe.MatchString(p.Archive) || !strings.HasSuffix(p.Archive, ".tar.gz") {
		return rpc.XferExportResult{}, errf("xfer_invalid_archive", "invalid archive name")
	}
	var man xfer.Manifest
	if err := json.Unmarshal(p.Manifest, &man); err != nil || man.Account.Username != p.User {
		return rpc.XferExportResult{}, errf("bad_params", "manifest")
	}
	e, err := lookupUser(p.User)
	if err != nil {
		return rpc.XferExportResult{}, err
	}
	for _, d := range p.Databases {
		if err := checkOwned(p.User, d, "invalid_db_name"); err != nil {
			return rpc.XferExportResult{}, err
		}
	}
	for _, b := range p.Blobs {
		c, err := xfer.CleanName(b.Name)
		if err != nil || !(strings.HasPrefix(c, "dnszones/") || strings.HasPrefix(c, "mail/") || strings.HasPrefix(c, "ssl/")) || len(b.Content) > 4<<20 {
			return rpc.XferExportResult{}, errf("bad_params", "blob %q", b.Name)
		}
	}
	if err := os.MkdirAll(xferDir, 0o700); err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	dest := filepath.Join(xferDir, p.Archive)
	if _, err := os.Lstat(dest); err == nil {
		return rpc.XferExportResult{}, errf("already_exists", "archive exists")
	}
	tmp, err := os.MkdirTemp(xferDir, ".export-")
	if err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	defer os.RemoveAll(tmp)
	f, err := os.OpenFile(filepath.Join(tmp, "a.tar.gz"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	w := xfer.NewWriter(gz)
	files := 0
	if err := xferAddHome(ctx, w, e, &files); err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	if len(p.Databases) > 0 {
		dump := mysqlClient("mariadb-dump", "mysqldump")
		if dump == "" {
			return rpc.XferExportResult{}, errf("not_installed", "mariadb-dump is not installed")
		}
		for _, d := range p.Databases {
			if err := xferAddDump(ctx, w, dump, d, tmp); err != nil {
				return rpc.XferExportResult{}, err
			}
			files++
		}
	}
	for _, b := range p.Blobs {
		if err := w.AddBytes(b.Name, []byte(b.Content)); err != nil {
			return rpc.XferExportResult{}, xferErr(err)
		}
		files++
	}
	man.CreatedAt = time.Now().Unix()
	man.SourceHost = a.Cfg.Hostname
	if err := w.Close(man); err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	if err := gz.Close(); err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	if err := f.Close(); err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	if err := os.Rename(f.Name(), dest); err != nil {
		return rpc.XferExportResult{}, xferErr(err)
	}
	fi, _ := os.Stat(dest)
	var sz int64
	if fi != nil {
		sz = fi.Size()
	}
	return rpc.XferExportResult{Archive: p.Archive, Bytes: sz, Files: files}, nil
}

// xferAddHome adds the home below homedir/. Only files owned by the account
// are read (a hard link to a foreign file is skipped); symlinks are stored as
// links (never followed) and only when they stay inside the home.
func xferAddHome(ctx context.Context, w *xfer.Writer, e passwdEntry, files *int) error {
	root, err := os.OpenRoot(e.home)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := w.AddDir("homedir", 0o750); err != nil {
		return err
	}
	return fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skipped
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if rel == "." {
			return nil
		}
		if rel == ".ssh" {
			return fs.SkipDir
		}
		name := "homedir/" + rel
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			t, err := root.Readlink(rel)
			if err == nil {
				return w.AddSymlink(name, t)
			}
			return nil
		case d.IsDir():
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			return w.AddDir(name, int64(fi.Mode().Perm()))
		case !d.Type().IsRegular():
			return nil // sockets, fifos, devices
		}
		fh, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil
		}
		defer fh.Close()
		fi, err := fh.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && int(st.Uid) != e.uid {
			return nil
		}
		if err := w.AddFile(name, int64(fi.Mode().Perm()), fi.Size(), fh); err != nil {
			return err
		}
		*files++
		return nil
	})
}

func xferAddDump(ctx context.Context, w *xfer.Writer, bin, dbName, tmp string) error {
	out := filepath.Join(tmp, "dump.sql")
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return xferErr(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Hour)
	defer cancel()
	// no --databases: the dump carries no CREATE DATABASE / USE statements
	cmd := exec.CommandContext(cctx, bin, "--single-transaction", "--quick", "--routines", "--triggers",
		"--no-tablespaces", "--skip-lock-tables", "--default-character-set=utf8mb4", "--", dbName)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/root"}
	cmd.Stdout = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()
	f.Close()
	if err != nil {
		return errf("xfer_db_export_failed", "%s: %s", dbName, strings.TrimSpace(lastLines(stderr.String(), 2)))
	}
	r, err := os.Open(out)
	if err != nil {
		return xferErr(err)
	}
	defer r.Close()
	fi, _ := r.Stat()
	if err := w.AddFile("mysql/"+dbName+".sql", 0o600, fi.Size(), r); err != nil {
		return xferErr(err)
	}
	return os.Remove(out)
}
