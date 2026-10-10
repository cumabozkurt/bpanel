//go:build !dev

package main

import (
	"errors"

	"github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/api"
)

// Production build: no mock agent, no demo data, no demo password (CODE-8).

func devPreflight(string) error {
	return errors.New("this binary was built without development support; rebuild with: go build -tags dev ./cmd/bpanel-api")
}

func devAgent(string) agentrpc.Caller { panic("unreachable: dev mode not compiled in") }

func devSeed(*api.Server, string) error { return errors.New("dev mode not compiled in") }
