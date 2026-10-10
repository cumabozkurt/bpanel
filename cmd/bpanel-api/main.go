// Command bpanel-api is the unprivileged web/API process of BOZKURT PANEL.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cumabozkurt/bpanel/internal/redact"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/api"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/version"
	"github.com/cumabozkurt/bpanel/internal/webui"
)

func main() {
	cfgPath := flag.String("config", "/etc/bpanel/api.json", "configuration file")
	dev := flag.Bool("dev", false, "development mode: in-process mock agent, demo data, no root needed (only in binaries built with -tags dev)")
	devDir := flag.String("dev-dir", "./dev-data", "data directory for --dev")
	plain := flag.Bool("plain-http", false, "serve plain HTTP on the panel ports (development only)")
	userPort := flag.Int("user-port", 0, "override the user panel port (default 2083)")
	adminPort := flag.Int("admin-port", 0, "override the admin panel port (default 2087)")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println("bpanel-api", version.Version, version.Commit)
		return
	}
	log := slog.New(redact.NewHandler(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))) // v0.4: redact secrets
	// R2-PERF-1: a soft memory limit (GC works harder before RSS grows past
	// it) unless the unit sets GOMEMLIMIT; MemoryMax= in the unit is the hard cap.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(384 << 20)
	}
	cfg := api.DefaultConfig()
	if *dev {
		// The mock agent and demo data are compiled only into dev builds
		// (CODE-8): a production binary can never serve a fake agent with a
		// known admin password, whatever flags it is started with.
		if err := devPreflight(*cfgPath); err != nil {
			log.Error("refusing --dev", "err", err)
			os.Exit(2)
		}
		if err := os.MkdirAll(*devDir, 0o755); err != nil {
			log.Error("dev dir", "err", err)
			os.Exit(1)
		}
		cfg.DBPath = filepath.Join(*devDir, "bpanel.db")
		// The secret store master key would default to /etc/bpanel/secret.key,
		// which a non-root dev run cannot create: keep it in the dev dir.
		cfg.SecretKeyFile = filepath.Join(*devDir, "secret.key")
		cfg.Dev = true
		cfg.Bind = "127.0.0.1" // never reachable from the network
		cfg.Hostname = "server.example.com"
		cfg.ServerIP = "203.0.113.10"
		cfg.TLSCert, cfg.TLSKey = "", ""
	} else if b, err := os.ReadFile(*cfgPath); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Error("bad config", "err", err)
			os.Exit(1)
		}
	} else {
		log.Error("cannot read config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	if *plain {
		cfg.PlainHTTP = true
	}
	if *userPort != 0 {
		cfg.UserPort = *userPort
	}
	if *adminPort != 0 {
		cfg.AdminPort = *adminPort
	}
	if os.Geteuid() == 0 {
		log.Warn("bpanel-api is running as root; it is designed to run as the unprivileged 'bpanel' user")
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	if err := api.Bootstrap(st); err != nil {
		log.Error("bootstrap", "err", err)
		os.Exit(1)
	}
	var agent agentrpc.Caller
	if *dev {
		agent = devAgent(*devDir)
	} else {
		// fail fast while the agent is down or hung (R2-PERF-6)
		agent = agentrpc.NewBreaker(agentrpc.NewClient(cfg.AgentSocket))
	}
	srv := api.New(cfg, st, agent, webui.FS(), log, version.Version)
	if *dev {
		if err := devSeed(srv, *devDir); err != nil {
			log.Error("seed", "err", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}
