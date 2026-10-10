// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"errors"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func TestRegistryDuplicateAndInvalid(t *testing.T) {
	r := NewRegistry()
	p := &Builtin{ID: "x", K: WebServer, Lic: oss("MIT", "u")}
	if err := r.Add(p); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(p); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := r.Add(&Builtin{ID: "", K: WebServer, Lic: oss("MIT", "u")}); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := r.Add(&Builtin{ID: "k", K: "nope", Lic: oss("MIT", "u")}); err == nil {
		t.Fatal("bad kind accepted")
	}
	if err := r.Add(&Builtin{ID: "l", K: DNS, Lic: License{Class: "free"}}); err == nil {
		t.Fatal("bad license accepted")
	}
	if err := r.Add(nil); err == nil {
		t.Fatal("nil accepted")
	}
}

func TestBuiltinsRegistered(t *testing.T) {
	want := []string{"nginx", "apache", "php-fpm", "mariadb", "powerdns", "postfix", "dovecot", "rspamd", "fail2ban", "restic", "lego", "imunify360", "monarx"}
	for _, n := range want {
		p, ok := Default.Get(n)
		if !ok {
			t.Fatalf("%s not registered", n)
		}
		if len(p.Capabilities()) == 0 || p.License().Upstream == "" {
			t.Errorf("%s: missing capabilities/upstream", n)
		}
	}
	for _, n := range []string{"imunify360", "monarx"} {
		p, _ := Default.Get(n)
		if p.License().Class != CommercialOptional {
			t.Errorf("%s should be commercial_optional", n)
		}
	}
	for _, n := range []string{"nftables", "clamav", "cgroups"} {
		if _, ok := (func() (Provider, bool) {
			r := NewRegistry()
			for _, p := range Builtins() {
				_ = r.Add(p)
			}
			return r.Get(n)
		})(); ok {
			t.Errorf("%s must not be a builtin", n)
		}
	}
}

func TestFromProbe(t *testing.T) {
	cases := []struct {
		name   string
		p      *rpc.ProviderProbe
		err    error
		state  State
		reason string
	}{
		{"agent_err", nil, errors.New("dial"), HealthFailed, "agent_unreachable"},
		{"outdated", nil, &rpc.Error{Code: "unknown_method"}, HealthFailed, "agent_outdated"},
		{"nil", nil, nil, HealthFailed, "not_probed"},
		{"unsupported", &rpc.ProviderProbe{Present: true, Unsupported: "no_systemd"}, nil, UnsupportedEnv, "no_systemd"},
		{"absent", &rpc.ProviderProbe{}, nil, NotInstalled, ""},
		{"problem", &rpc.ProviderProbe{Present: true, Configured: true, Problem: "version_check_failed"}, nil, HealthFailed, "version_check_failed"},
		{"failed", &rpc.ProviderProbe{Present: true, Configured: true, Unit: "nginx", UnitState: "failed"}, nil, HealthFailed, "service_failed"},
		{"inactive", &rpc.ProviderProbe{Present: true, Configured: true, UnitState: "inactive"}, nil, HealthFailed, "service_inactive"},
		{"unconfigured", &rpc.ProviderProbe{Present: true}, nil, NotConfigured, "bpanel_config_missing"},
		{"ok", &rpc.ProviderProbe{Present: true, Configured: true, Version: "1.26.2", UnitState: "active"}, nil, Installed, ""},
	}
	for _, c := range cases {
		st := FromProbe(c.p, c.err)
		if st.State != c.state || st.Reason != c.reason {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, st.State, st.Reason, c.state, c.reason)
		}
	}
	st := FromProbe(&rpc.ProviderProbe{Present: true, Configured: true, Version: "1.2.3", Binary: "/usr/sbin/nginx", Unit: "nginx", UnitState: "active"}, nil)
	if st.Version != "1.2.3" || st.Detail != "/usr/sbin/nginx · nginx (active)" {
		t.Errorf("detail/version: %+v", st)
	}
}

type fakeCaller struct {
	res   rpc.ProvidersDetectResult
	calls int
}

func (f *fakeCaller) Call(ctx context.Context, m string, p, out any) error {
	f.calls++
	if m != rpc.MProvidersDetect {
		return errors.New("unexpected")
	}
	*(out.(*rpc.ProvidersDetectResult)) = f.res
	return nil
}

type panicky struct{ Builtin }

func (p *panicky) Detect(context.Context, *Env) Status { panic("boom") }

func TestDetectAll(t *testing.T) {
	r := NewRegistry()
	for _, p := range Builtins() {
		_ = r.Add(p)
	}
	_ = r.Add(&panicky{Builtin{ID: "zz", K: Monitoring, Lic: oss("MIT", "u")}})
	fc := &fakeCaller{res: rpc.ProvidersDetectResult{Probes: []rpc.ProviderProbe{
		{Component: "nginx", Present: true, Configured: true, Version: "1.26.2"},
		{Component: "monarx", Present: true, Binary: "/usr/bin/monarx-agent"},
	}}}
	reps := r.DetectAll(context.Background(), NewEnv(fc, nil), time.Second)
	if fc.calls != 1 {
		t.Fatalf("agent called %d times", fc.calls)
	}
	got := map[string]Report{}
	for _, x := range reps {
		got[x.Name] = x
	}
	if got["nginx"].State != Installed || got["nginx"].Version != "1.26.2" {
		t.Errorf("nginx %+v", got["nginx"])
	}
	if got["monarx"].State != Installed {
		t.Errorf("monarx %+v", got["monarx"])
	}
	if got["apache"].State != HealthFailed || got["apache"].Reason != "not_probed" {
		t.Errorf("apache %+v", got["apache"])
	}
	if got["zz"].Reason != "detector_crashed" {
		t.Errorf("panic %+v", got["zz"])
	}
	if reps[0].Kind != WebServer {
		t.Errorf("order: %s first", reps[0].Kind)
	}
	// no agent at all
	reps = r.DetectAll(context.Background(), NewEnv(nil, nil), time.Second)
	for _, x := range reps {
		if x.State == Installed {
			t.Errorf("%s installed without agent", x.Name)
		}
	}
}
