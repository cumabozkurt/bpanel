// SPDX-License-Identifier: Apache-2.0

package agentrpc

// MProvidersDetect asks the agent which server components are present, their
// versions and the state of their systemd units. It is read-only: the agent
// stats fixed binary paths and runs `<binary> --version` (argv, no shell) with
// a short timeout; it never installs, starts or reconfigures anything
// (v0.4 provider framework, docs/architecture.md).
const MProvidersDetect = "providers.detect"

// ProviderProbe is what the agent found for one component.
type ProviderProbe struct {
	// Component is the provider name the API registered ("nginx", "php-fpm" …).
	Component string `json:"component"`
	// Present: one of the component's fixed binary paths exists.
	Present bool   `json:"present"`
	Binary  string `json:"binary,omitempty"`
	// Version as parsed from the version command ("1.26.2"); for multi-version
	// components (PHP-FPM) a comma separated list.
	Version string `json:"version,omitempty"`
	// Unit / UnitState: systemd unit and its ActiveState ("active", "failed",
	// "inactive" …); empty when the agent runs without systemd.
	Unit      string `json:"unit,omitempty"`
	UnitState string `json:"unit_state,omitempty"`
	// Configured is false when BPANEL's own configuration for the component is
	// missing (e.g. no PowerDNS API key in agent.json).
	Configured bool `json:"configured"`
	// Problem is a short machine reason when a check failed
	// ("version_check_failed", "api_unreachable"); never contains secrets.
	Problem string `json:"problem,omitempty"`
	// Unsupported is set when the component cannot run in this environment.
	Unsupported string `json:"unsupported,omitempty"`
}

type ProvidersDetectResult struct {
	Distro  string          `json:"distro"`
	Family  string          `json:"family"`
	Systemd bool            `json:"systemd"`
	Probes  []ProviderProbe `json:"probes"`
}
