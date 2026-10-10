//go:build dev

package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/api"
	"github.com/cumabozkurt/bpanel/internal/mockagent"
)

// devPreflight refuses dev mode where it could be mistaken for production.
func devPreflight(cfgPath string) error {
	if os.Geteuid() == 0 {
		return errors.New("dev mode must not run as root")
	}
	if _, err := os.Stat(cfgPath); err == nil && cfgPath == "/etc/bpanel/api.json" {
		return errors.New("/etc/bpanel/api.json exists: this looks like an installed server")
	}
	return nil
}

func devAgent(devDir string) agentrpc.Caller {
	return mockagent.New(filepath.Join(devDir, "homes"))
}

func devSeed(srv *api.Server, devDir string) error { return seedDemo(srv, devDir) }
