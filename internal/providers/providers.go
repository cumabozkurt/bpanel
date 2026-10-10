// SPDX-License-Identifier: Apache-2.0

// Package providers is BPANEL's integration registry (master spec §19).
//
// Every server component BPANEL drives or can integrate with (web server,
// PHP, DNS, mail, database, malware scanner, isolation, firewall, WAF,
// backup, monitoring, certificates, secret store …) is described by a
// Provider: its kind, its license class, what it can do and how to find out
// whether it is present and healthy on this server.
//
// Detection never pretends: a component that is absent reports
// not_installed, one BPANEL has not been set up for reports not_configured,
// one that cannot run here reports unsupported_env with a reason, and a
// failed check reports health_failed with a reason. Detection that needs
// root goes through the agent (typed action providers.detect, see
// internal/agent/providers.go); a Provider itself only reads.
//
// Other packages add their own providers with providers.Register(p) from an
// init function (clamav, nftables, cgroups …).
package providers

import (
	"context"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// Kind groups providers by the role they play (spec §19 interface list).
type Kind string

const (
	WebServer       Kind = "web_server"
	PHP             Kind = "php"
	DNS             Kind = "dns"
	Mail            Kind = "mail"
	Database        Kind = "database"
	MalwareScanner  Kind = "malware_scanner"
	Isolation       Kind = "isolation"
	ResourceManager Kind = "resource_manager"
	Firewall        Kind = "firewall"
	WAF             Kind = "waf"
	Backup          Kind = "backup"
	Monitoring      Kind = "monitoring"
	Certificate     Kind = "certificate"
	SecretStore     Kind = "secret_store"
)

// Kinds lists every kind in display order.
var Kinds = []Kind{WebServer, PHP, DNS, Mail, Database, MalwareScanner, Isolation, ResourceManager,
	Firewall, WAF, Backup, Monitoring, Certificate, SecretStore}

// ValidKind reports whether k is one of Kinds.
func ValidKind(k Kind) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// LicenseClass is the §19 license badge.
type LicenseClass string

const (
	// OpenSource: free and open source, usable without an extra product license.
	OpenSource LicenseClass = "open_source"
	// CommercialOptional: an external commercial product that needs its own
	// license; BPANEL only integrates through its official interfaces.
	CommercialOptional LicenseClass = "commercial_optional"
)

// License describes the upstream license of a component.
type License struct {
	Class    LicenseClass `json:"class"`
	SPDX     string       `json:"spdx"`     // e.g. "BSD-2-Clause"; "proprietary" for commercial
	Upstream string       `json:"upstream"` // official project or vendor URL
	// Bundled: shipped inside BPANEL's own binaries (Go module) as opposed to
	// a separate program installed from the OS / vendor repository.
	Bundled bool `json:"bundled"`
}

// State is the detection result (§19 badges).
type State string

const (
	Installed      State = "installed"       // Yerel olarak kurulu
	NotInstalled   State = "not_installed"   // Kurulu değil
	NotConfigured  State = "not_configured"  // Yapılandırılmamış
	UnsupportedEnv State = "unsupported_env" // Desteklenmeyen ortam
	HealthFailed   State = "health_failed"   // Sağlık kontrolü başarısız
)

// Status is what Detect returns.
type Status struct {
	State   State  `json:"state"`
	Version string `json:"version,omitempty"`
	// Reason is a short machine code (translated by the UI as prov.reason.<code>).
	Reason string `json:"reason,omitempty"`
	// Detail is non-sensitive context (binary path, unit and its state).
	Detail string `json:"detail,omitempty"`
}

// Provider is implemented by every integration.
type Provider interface {
	// Name is unique across the registry ("nginx", "clamav").
	Name() string
	// Title is the human product name ("Nginx").
	Title() string
	Kind() Kind
	License() License
	// Capabilities lists what BPANEL actually does with the component today
	// (machine codes, e.g. "vhosts", "config_test"); planned work is not listed.
	Capabilities() []string
	// Requirements lists OS/kernel requirements in plain words.
	Requirements() []string
	// Detect reports the component's state. It must be read-only, honour ctx
	// and never return a fake success.
	Detect(ctx context.Context, env *Env) Status
}

// Env is what Detect may use. Agent snapshots are fetched once per Env.
type Env struct {
	Agent rpc.Caller
	// Features is the install profile's feature map (feature_<name> settings);
	// nil = unknown.
	Features map[string]bool

	snap    *rpc.ProvidersDetectResult
	snapErr error
	fetched bool
}

// NewEnv returns an Env that asks agent for its snapshot on first use.
func NewEnv(agent rpc.Caller, features map[string]bool) *Env {
	return &Env{Agent: agent, Features: features}
}

// Snapshot returns the agent's providers.detect result (memoised).
// Not safe for concurrent first use; DetectAll calls it before fanning out.
func (e *Env) Snapshot(ctx context.Context) (*rpc.ProvidersDetectResult, error) {
	if e.fetched {
		return e.snap, e.snapErr
	}
	e.fetched = true
	if e.Agent == nil {
		e.snapErr = errNoAgent
		return nil, e.snapErr
	}
	var r rpc.ProvidersDetectResult
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := e.Agent.Call(cctx, rpc.MProvidersDetect, rpc.Empty{}, &r); err != nil {
		e.snapErr = err
		return nil, err
	}
	e.snap = &r
	return e.snap, nil
}

// Probe returns the agent probe for one component, or nil.
func (e *Env) Probe(ctx context.Context, name string) (*rpc.ProviderProbe, error) {
	s, err := e.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	for i := range s.Probes {
		if s.Probes[i].Component == name {
			return &s.Probes[i], nil
		}
	}
	return nil, nil
}

type envErr string

func (e envErr) Error() string { return string(e) }

const errNoAgent = envErr("no agent")
