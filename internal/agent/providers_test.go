// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProvidersDetectFakeBinaries(t *testing.T) {
	dir := t.TempDir()
	ng := script(t, dir, "nginx", `echo "nginx version: nginx/1.26.2" >&2`)
	bad := script(t, dir, "broken", `echo "garbage"; exit 3`)
	php1 := script(t, dir, "php8.2", `echo "PHP 8.2.20 (fpm-fcgi)"`)
	php2 := script(t, dir, "php8.3", `echo "PHP 8.3.9 (fpm-fcgi)"`)
	comm := script(t, dir, "commercial", `touch `+filepath.Join(dir, "EXECUTED"))
	healthCalled := false
	probeSpecsHook = func(a *Agent) []probeSpec {
		return []probeSpec{
			{name: "nginx", bins: []string{ng}, args: []string{"-v"}, re: regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`), unit: "nginx", configured: func() bool { return true }},
			{name: "broken", bins: []string{bad}, args: []string{"--version"}, configured: func() bool { return true },
				health: func(context.Context) string { healthCalled = true; return "" }},
			{name: "php-fpm", bins: []string{php1, filepath.Join(dir, "missing"), php2}, multi: true, args: []string{"-v"}, re: regexp.MustCompile(`PHP (\d+\.\d+\.\d+)`)},
			{name: "absent", bins: []string{filepath.Join(dir, "nope"), "relative/bin"}, args: []string{"-v"}},
			{name: "unconf", bins: []string{ng}, args: []string{"-v"}, configured: func() bool { return false },
				health: func(context.Context) string { healthCalled = true; return "x" }},
			{name: "monarx", bins: []string{comm}, existsOnly: true, configured: func() bool { return true }},
			{name: "lego", embedded: func() (string, bool) { return "4.21.0", true }},
		}
	}
	t.Cleanup(func() { probeSpecsHook = nil })
	a := &Agent{Cfg: Config{NoSystemd: true}}
	res, err := a.providersDetect(context.Background(), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Systemd {
		t.Error("systemd reported with NoSystemd")
	}
	got := map[string]int{}
	for i, p := range res.Probes {
		got[p.Component] = i
	}
	pr := func(n string) (p struct {
		Present, Configured     bool
		Version, Problem, Unit_ string
	}) {
		x := res.Probes[got[n]]
		p.Present, p.Configured, p.Version, p.Problem, p.Unit_ = x.Present, x.Configured, x.Version, x.Problem, x.UnitState
		return
	}
	if p := pr("nginx"); !p.Present || p.Version != "1.26.2" || p.Problem != "" || !p.Configured || p.Unit_ != "" {
		t.Errorf("nginx %+v", p)
	}
	if p := pr("broken"); !p.Present || p.Problem != "version_check_failed" || p.Version != "" {
		t.Errorf("broken %+v", p)
	}
	if healthCalled {
		t.Error("health ran after failed version check / on unconfigured component")
	}
	if p := pr("php-fpm"); p.Version != "8.2.20, 8.3.9" {
		t.Errorf("php %+v", p)
	}
	if p := pr("absent"); p.Present {
		t.Errorf("absent %+v", p)
	}
	if p := pr("unconf"); p.Configured {
		t.Errorf("unconf %+v", p)
	}
	if p := pr("monarx"); !p.Present || p.Version != "" {
		t.Errorf("monarx %+v", p)
	}
	if _, err := os.Stat(filepath.Join(dir, "EXECUTED")); err == nil {
		t.Error("existsOnly binary was executed")
	}
	if p := pr("lego"); !p.Present || p.Version != "4.21.0" {
		t.Errorf("lego %+v", p)
	}
	for i := 1; i < len(res.Probes); i++ {
		if res.Probes[i-1].Component > res.Probes[i].Component {
			t.Error("probes not sorted")
		}
	}
}
