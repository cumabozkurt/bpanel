// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// Registry holds providers by name.
type Registry struct {
	mu sync.RWMutex
	m  map[string]Provider
}

func NewRegistry() *Registry { return &Registry{m: map[string]Provider{}} }

// Default is the process-wide registry Register adds to.
var Default = NewRegistry()

// Register adds p to the default registry. It panics on a programming error
// (empty or duplicate name, unknown kind or license class), so a broken
// provider fails every test run instead of silently disappearing.
func Register(p Provider) {
	if err := Default.Add(p); err != nil {
		panic(err)
	}
}

// Add adds p, refusing duplicates and invalid descriptions.
func (r *Registry) Add(p Provider) error {
	if p == nil || p.Name() == "" {
		return errors.New("providers: empty provider name")
	}
	if !ValidKind(p.Kind()) {
		return fmt.Errorf("providers: %s: unknown kind %q", p.Name(), p.Kind())
	}
	if c := p.License().Class; c != OpenSource && c != CommercialOptional {
		return fmt.Errorf("providers: %s: unknown license class %q", p.Name(), c)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.m[p.Name()]; dup {
		return fmt.Errorf("providers: %s registered twice", p.Name())
	}
	r.m[p.Name()] = p
	return nil
}

// Get returns one provider.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.m[name]
	return p, ok
}

// All returns every provider sorted by kind order, then name.
func (r *Registry) All() []Provider {
	r.mu.RLock()
	out := make([]Provider, 0, len(r.m))
	for _, p := range r.m {
		out = append(out, p)
	}
	r.mu.RUnlock()
	order := map[Kind]int{}
	for i, k := range Kinds {
		order[k] = i
	}
	sort.Slice(out, func(i, j int) bool {
		if order[out[i].Kind()] != order[out[j].Kind()] {
			return order[out[i].Kind()] < order[out[j].Kind()]
		}
		return out[i].Name() < out[j].Name()
	})
	return out
}

// ByKind returns the providers of one kind.
func (r *Registry) ByKind(k Kind) []Provider {
	var out []Provider
	for _, p := range r.All() {
		if p.Kind() == k {
			out = append(out, p)
		}
	}
	return out
}

// Report is one provider with its detection result (the API shape).
type Report struct {
	Name         string   `json:"name"`
	Title        string   `json:"title"`
	Kind         Kind     `json:"kind"`
	License      License  `json:"license"`
	Capabilities []string `json:"capabilities"`
	Requirements []string `json:"requirements"`
	Status
}

// DetectAll runs every provider's Detect with a per-provider timeout. The
// agent snapshot is fetched once before the fan-out. A panicking provider
// reports health_failed instead of taking the API down.
func (r *Registry) DetectAll(ctx context.Context, env *Env, perProvider time.Duration) []Report {
	if env == nil {
		env = &Env{}
	}
	_, _ = env.Snapshot(ctx) // memoise; errors are mapped per provider
	ps := r.All()
	out := make([]Report, len(ps))
	var wg sync.WaitGroup
	for i, p := range ps {
		out[i] = Report{Name: p.Name(), Title: p.Title(), Kind: p.Kind(), License: p.License(),
			Capabilities: nonNil(p.Capabilities()), Requirements: nonNil(p.Requirements())}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					out[i].Status = Status{State: HealthFailed, Reason: "detector_crashed"}
					_ = debug.Stack()
				}
			}()
			cctx, cancel := context.WithTimeout(ctx, perProvider)
			defer cancel()
			st := p.Detect(cctx, env)
			if st.State == "" {
				st = Status{State: HealthFailed, Reason: "no_result"}
			}
			if cctx.Err() != nil && st.State == Installed {
				st = Status{State: HealthFailed, Reason: "timeout"}
			}
			out[i].Status = st
		}()
	}
	wg.Wait()
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// FromProbe maps an agent probe (or the error fetching it) to a Status.
// Precedence: agent error > not probed > unsupported > absent > failed
// check > failed/inactive unit > missing BPANEL configuration > installed.
func FromProbe(p *rpc.ProviderProbe, err error) Status {
	if err != nil {
		var re *rpc.Error
		if errors.As(err, &re) && re.Code == "unknown_method" {
			return Status{State: HealthFailed, Reason: "agent_outdated"}
		}
		return Status{State: HealthFailed, Reason: "agent_unreachable"}
	}
	if p == nil {
		return Status{State: HealthFailed, Reason: "not_probed"}
	}
	detail := ""
	if p.Binary != "" {
		detail = p.Binary
	}
	if p.Unit != "" && p.UnitState != "" {
		if detail != "" {
			detail += " · "
		}
		detail += p.Unit + " (" + p.UnitState + ")"
	}
	st := Status{Version: p.Version, Detail: detail}
	switch {
	case p.Unsupported != "":
		st.State, st.Reason = UnsupportedEnv, p.Unsupported
	case !p.Present:
		st = Status{State: NotInstalled}
	case p.Problem != "":
		st.State, st.Reason = HealthFailed, p.Problem
	case p.UnitState == "failed":
		st.State, st.Reason = HealthFailed, "service_failed"
	case p.UnitState == "inactive" || p.UnitState == "deactivating":
		st.State, st.Reason = HealthFailed, "service_inactive"
	case !p.Configured:
		st.State, st.Reason = NotConfigured, "bpanel_config_missing"
	default:
		st.State = Installed
	}
	return st
}
