// Command bpanel-agent is the root-privileged executor of BOZKURT PANEL. It
// listens only on a unix socket and accepts typed requests from bpanel-api.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/cumabozkurt/bpanel/internal/agent"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/isolation"
	"github.com/cumabozkurt/bpanel/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "files-helper" {
		os.Exit(agent.RunFileHelper())
	}
	if len(os.Args) > 1 && os.Args[1] == "join" { // v0.4 msrv: enrol this node with a panel
		os.Exit(agent.RunJoin(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "cage-exec" { // isolation: cron cage fallback without systemd
		os.Exit(isolation.CageExecMain(os.Args[2:]))
	}
	cfgPath := flag.String("config", "/etc/bpanel/agent.json", "configuration file")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println("bpanel-agent", version.Version, version.Commit)
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// R2-WB-6: soft memory limit unless the unit sets GOMEMLIMIT (the unit's
	// MemoryMax= is the hard cap); request buffering is bounded in Serve.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(256 << 20)
	}
	if os.Geteuid() != 0 {
		log.Error("bpanel-agent must run as root")
		os.Exit(1)
	}
	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		log.Error("config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	l, err := distro.Detect()
	if err != nil {
		log.Error("distro", "err", err)
		os.Exit(1)
	}
	agent.Version = version.Version
	a := agent.New(cfg, l, log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.StartRemote(ctx); err != nil { // v0.4 msrv: opt-in mTLS listener
		log.Error("remote listener", "err", err)
		os.Exit(1)
	}
	if err := a.Serve(ctx); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
