// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/netsec"
)

// fakeNft records argv and keeps "table inet bpanel" in a file.
const fakeNft = `#!/bin/sh
D=$(dirname "$0")
echo "$*" >> "$D/argv.log"
case "$1" in
  -c) [ -f "$D/fail_check" ] && { echo "Error: syntax error" >&2; exit 1; }; exit 0;;
  -f) [ -f "$D/fail_apply" ] && { echo "Error: kernel" >&2; exit 1; }
      grep -v -e '^#' -e '^table inet bpanel {}$' -e '^delete table inet bpanel$' "$2" > "$D/table.tmp"
      if [ -s "$D/table.tmp" ]; then mv "$D/table.tmp" "$D/table"; else rm -f "$D/table" "$D/table.tmp"; fi
      exit 0;;
  list) if [ -s "$D/table" ]; then cat "$D/table"; exit 0; fi
        echo "Error: No such file or directory; did you mean table 'x'?" >&2; exit 1;;
  -j) if [ "$6" = "block4" ]; then
        echo '{"nftables":[{"set":{"name":"block4","elem":[{"elem":{"val":"192.0.2.50","timeout":3600,"expires":3590}}]}}]}'
      else echo '{"nftables":[{"set":{"name":"block6"}}]}'; fi; exit 0;;
  add|delete) exit 0;;
esac
exit 2
`

type fwEnv struct {
	dir, bin, state string
	a               *Agent
}

func newFwEnv(t *testing.T) *fwEnv {
	t.Helper()
	d := t.TempDir()
	bin := filepath.Join(d, "nft")
	if err := os.WriteFile(bin, []byte(fakeNft), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBins, oldMin := nftBins, fwConfirmMin
	nftBins, fwConfirmMin = []string{bin}, time.Second
	t.Cleanup(func() { nftBins, fwConfirmMin = oldBins, oldMin })
	state := filepath.Join(d, "state")
	return &fwEnv{dir: d, bin: bin, state: state, a: newFwAgent(state)}
}

func newFwAgent(state string) *Agent {
	return New(Config{NetsecDir: state, NoSystemd: true}, &distro.Layout{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func fwRuleset() netsec.Ruleset {
	return netsec.Ruleset{SSHPort: 22, PanelPorts: []int{8443}, AdminIP: "203.0.113.7",
		Rules: []netsec.Rule{{Action: netsec.ActionDeny, CIDR: "198.51.100.0/24"}}}
}

func (e *fwEnv) table(t *testing.T) string {
	b, err := os.ReadFile(filepath.Join(e.dir, "table"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const oldTable = "table inet bpanel {\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n\t}\n}\n"

func TestNetsecApplyNoConfirmRollsBack(t *testing.T) {
	e := newFwEnv(t)
	_ = os.WriteFile(filepath.Join(e.dir, "table"), []byte(oldTable), 0o644)
	res, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset(), ConfirmSeconds: 1})
	if err != nil || res.Status != "pending" || res.Token == "" || !res.SyntaxOK {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(e.table(t), "198.51.100.0/24") {
		t.Fatal("new ruleset not applied")
	}
	if _, err := os.Stat(filepath.Join(e.state, "pending.json")); err != nil {
		t.Fatal("pending state not persisted")
	}
	// a second apply while pending is refused
	if _, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset(), ConfirmSeconds: 1}); err == nil || !strings.Contains(err.Error(), "fw_pending") {
		t.Fatalf("second apply: %v", err)
	}
	time.Sleep(1600 * time.Millisecond)
	if got := e.table(t); got != oldTable {
		t.Fatalf("rollback did not restore snapshot:\n%q", got)
	}
	st, _ := e.a.fwStatus(context.Background(), rpc.NetsecFwStatusParams{})
	if st.Pending || st.LastRollback != "timeout" || !st.Supported {
		t.Fatalf("status %+v", st)
	}
	if _, err := e.a.fwConfirm(context.Background(), rpc.NetsecFwConfirmParams{Token: res.Token}); err == nil {
		t.Fatal("confirm after rollback must fail")
	}
	log, _ := os.ReadFile(filepath.Join(e.dir, "argv.log"))
	for _, want := range []string{"-c -f " + filepath.Join(e.state, "next.nft"), "list table inet bpanel", "-f " + filepath.Join(e.state, "rollback.nft")} {
		if !strings.Contains(string(log), want) {
			t.Errorf("argv log lacks %q:\n%s", want, log)
		}
	}
	if fi, err := os.Stat(filepath.Join(e.state, "next.nft")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("script file mode: %v %v", fi, err)
	}
}

func TestNetsecApplyConfirmKeeps(t *testing.T) {
	e := newFwEnv(t)
	res, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset(), ConfirmSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.fwConfirm(context.Background(), rpc.NetsecFwConfirmParams{Token: "wrong"}); err == nil {
		t.Fatal("wrong token accepted")
	}
	if c, err := e.a.fwConfirm(context.Background(), rpc.NetsecFwConfirmParams{Token: res.Token}); err != nil || c.Status != "confirmed" {
		t.Fatal(c, err)
	}
	time.Sleep(1300 * time.Millisecond)
	if !strings.Contains(e.table(t), "198.51.100.0/24") {
		t.Fatal("confirmed ruleset was rolled back")
	}
	if _, err := os.Stat(filepath.Join(e.state, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("pending.json left behind")
	}
	// the confirmed admin IP is protected from temporary blocks
	if _, err := e.a.fwBlock(context.Background(), rpc.NetsecFwBlockParams{IP: "203.0.113.0/24", TimeoutSeconds: 60}); err == nil || !strings.Contains(err.Error(), netsec.CodeLockout) {
		t.Fatalf("admin block: %v", err)
	}
}

func TestNetsecRestartRollsBack(t *testing.T) {
	e := newFwEnv(t)
	res, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset(), ConfirmSeconds: 60})
	if err != nil || e.table(t) == "" {
		t.Fatal(res, err)
	}
	e.a.fw().timer.Stop()   // simulate the old process dying
	_ = newFwAgent(e.state) // new process: New() -> netsecRecover
	if got := e.table(t); got != "" {
		t.Fatalf("restart did not remove the unconfirmed table (no previous table existed):\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(e.state, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("pending.json not cleared")
	}
	b, _ := os.ReadFile(filepath.Join(e.state, "last_rollback"))
	if !strings.HasPrefix(string(b), "agent_restart") {
		t.Fatalf("last_rollback %q", b)
	}
}

func TestNetsecRefusals(t *testing.T) {
	e := newFwEnv(t)
	rs := fwRuleset()
	rs.Rules = append(rs.Rules, netsec.Rule{Action: netsec.ActionDeny, CIDR: "203.0.113.0/24"})
	if _, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: rs}); err == nil || !strings.Contains(err.Error(), netsec.CodeLockout) {
		t.Fatalf("lockout not refused: %v", err)
	}
	_ = os.WriteFile(filepath.Join(e.dir, "fail_check"), nil, 0o644)
	if _, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset()}); err == nil || !strings.Contains(err.Error(), "fw_invalid") {
		t.Fatalf("nft -c failure: %v", err)
	}
	_ = os.Remove(filepath.Join(e.dir, "fail_check"))
	_ = os.WriteFile(filepath.Join(e.dir, "fail_apply"), nil, 0o644)
	if _, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset()}); err == nil || !strings.Contains(err.Error(), "fw_apply_failed") {
		t.Fatalf("apply failure: %v", err)
	}
	if e.a.fw().pending != nil {
		t.Fatal("failed apply left a pending change")
	}
	if _, err := e.a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset(), ConfirmSeconds: 5000}); err == nil {
		t.Fatal("confirm window not bounded")
	}
}

func TestNetsecBlocks(t *testing.T) {
	e := newFwEnv(t)
	ctx := context.Background()
	if r, err := e.a.fwBlock(ctx, rpc.NetsecFwBlockParams{IP: "192.0.2.50", TimeoutSeconds: 3600}); err != nil || r.Status != "ok" {
		t.Fatal(r, err)
	}
	if r, err := e.a.fwUnblock(ctx, rpc.NetsecFwUnblockParams{IP: "2001:db8::1"}); err != nil || r.Status != "ok" {
		t.Fatal(r, err)
	}
	l, err := e.a.fwList(ctx, rpc.NetsecFwListParams{})
	if err != nil || l.Status != "ok" || len(l.Blocks) != 1 || l.Blocks[0].IP != "192.0.2.50" || l.Blocks[0].ExpiresAt.IsZero() {
		t.Fatalf("%+v %v", l, err)
	}
	log, _ := os.ReadFile(filepath.Join(e.dir, "argv.log"))
	for _, want := range []string{"add element inet bpanel block4 { 192.0.2.50 timeout 3600s }", "delete element inet bpanel block6 { 2001:db8::1 }", "-j list set inet bpanel block4"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("argv log lacks %q:\n%s", want, log)
		}
	}
	if _, err := e.a.fwBlock(ctx, rpc.NetsecFwBlockParams{IP: "1.2.3.4; rm -rf /", TimeoutSeconds: 60}); err == nil {
		t.Fatal("injection accepted")
	}
}

func TestNetsecUnsupportedWithoutNft(t *testing.T) {
	old := nftBins
	nftBins = []string{"/nonexistent/nft"}
	defer func() { nftBins = old }()
	a := newFwAgent(t.TempDir())
	res, err := a.fwApply(context.Background(), rpc.NetsecFwApplyParams{Ruleset: fwRuleset()})
	if err != nil || res.Status != "unsupported" || res.Reason != "nft_not_installed" || !res.SyntaxOK || res.Token != "" {
		t.Fatalf("%+v %v", res, err)
	}
	b, _ := a.fwBlock(context.Background(), rpc.NetsecFwBlockParams{IP: "192.0.2.1", TimeoutSeconds: 60})
	l, _ := a.fwList(context.Background(), rpc.NetsecFwListParams{})
	st, _ := a.fwStatus(context.Background(), rpc.NetsecFwStatusParams{})
	if b.Status != "unsupported" || l.Status != "unsupported" || st.Supported {
		t.Fatal(b, l, st)
	}
}

// TestNetsecRealKernelNetns applies the ruleset inside a throwaway network
// namespace with the real nft binary, then lets the confirm window lapse and
// checks the previous table is back. Skipped when nft or sudo is absent.
func TestNetsecRealKernelNetns(t *testing.T) {
	real := ""
	for _, b := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if _, err := os.Stat(b); err == nil {
			real = b
		}
	}
	if real == "" {
		t.Skip("nft not installed: real-kernel apply/rollback NOT verified")
	}
	if exec.Command("sudo", "-n", "true").Run() != nil {
		t.Skip("sudo -n unavailable")
	}
	holder := exec.Command("sudo", "-n", "unshare", "-n", "sleep", "60")
	if err := holder.Start(); err != nil {
		t.Skip("unshare -n failed: ", err)
	}
	defer func() { _ = holder.Process.Kill(); _ = holder.Wait() }()
	time.Sleep(300 * time.Millisecond)
	out, err := exec.Command("pgrep", "-n", "-f", "^sleep 60$").Output()
	if err != nil {
		t.Skip("cannot find netns holder")
	}
	pid := strings.TrimSpace(string(out))
	if _, err := strconv.Atoi(pid); err != nil {
		t.Skip("bad pid")
	}
	oldBins, oldPre, oldMin := nftBins, nftPrefix, fwConfirmMin
	nftBins, nftPrefix, fwConfirmMin = []string{real}, []string{"sudo", "-n", "nsenter", "-t", pid, "-n"}, time.Second
	defer func() { nftBins, nftPrefix, fwConfirmMin = oldBins, oldPre, oldMin }()
	a := newFwAgent(t.TempDir())
	ctx := context.Background()
	// previous table: a confirmed apply
	r1, err := a.fwApply(ctx, rpc.NetsecFwApplyParams{Ruleset: netsec.Ruleset{SSHPort: 22, PanelPorts: []int{8443}, AdminIP: "203.0.113.7"}, ConfirmSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.fwConfirm(ctx, rpc.NetsecFwConfirmParams{Token: r1.Token}); err != nil {
		t.Fatal(err)
	}
	before, _ := a.nft(ctx, "list", "table", "inet", "bpanel")
	if _, err := a.fwApply(ctx, rpc.NetsecFwApplyParams{Ruleset: fwRuleset(), ConfirmSeconds: 1}); err != nil {
		t.Fatal(err)
	}
	mid, _ := a.nft(ctx, "list", "table", "inet", "bpanel")
	if !strings.Contains(mid, "198.51.100.0/24") {
		t.Fatalf("not applied in netns:\n%s", mid)
	}
	time.Sleep(2 * time.Second)
	after, _ := a.nft(ctx, "list", "table", "inet", "bpanel")
	if after != before {
		t.Fatalf("rollback mismatch:\nbefore=%s\nafter=%s", before, after)
	}
	t.Log("real kernel netns apply + rollback verified")
}
