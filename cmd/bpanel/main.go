// Command bpanel is the administrator CLI (run as root on the server).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/api"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/installer"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/version"
)

const usage = `BOZKURT PANEL CLI

Usage:
  bpanel version
  bpanel login-link [--realm admin|user] [--user NAME] [--ttl 15m]   one-time login URL
  bpanel admin --user NAME [--password PW] [--email E]              create/reset a panel administrator
  bpanel selftest                                                   check agent, database and listeners
  bpanel doctor                                                     check the services v0.4 modules need (ok/missing)
  bpanel openapi                                                    print the OpenAPI document
  bpanel secrets status|migrate --to openbao|local                  secret provider status / copy+verify+switch
`

func loadCfg() api.Config {
	cfg := api.DefaultConfig()
	if b, err := os.ReadFile("/etc/bpanel/api.json"); err == nil {
		json.Unmarshal(b, &cfg)
	}
	return cfg
}

func openStore(cfg api.Config) *store.Store {
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "database:", err)
		os.Exit(1)
	}
	return st
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	cfg := loadCfg()
	switch cmd {
	case "version":
		fmt.Println("bpanel", version.Version, version.Commit)
	case "login-link":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		realm := fs.String("realm", "admin", "admin or user")
		user := fs.String("user", "bpadmin", "account name")
		ttl := fs.Duration("ttl", 15*time.Minute, "validity")
		fs.Parse(args)
		st := openStore(cfg)
		defer st.Close()
		var id int64
		if err := st.DB.QueryRow(`SELECT id FROM users WHERE username=?`, *user).Scan(&id); err != nil {
			fmt.Fprintln(os.Stderr, "no such user:", *user)
			os.Exit(1)
		}
		tok, err := api.CreateOnceToken(st, id, *realm, 0, *ttl)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		port := cfg.AdminPort
		if *realm == api.RealmUser {
			port = cfg.UserPort
		}
		host := cfg.Hostname
		if host == "" {
			host, _ = os.Hostname()
		}
		fmt.Printf("https://%s:%d/login/once/%s\n", host, port, tok)
	case "admin":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		user := fs.String("user", "bpadmin", "administrator name")
		pw := fs.String("password", "", "password (random if empty)")
		email := fs.String("email", "", "contact email")
		fs.Parse(args)
		if *pw == "" {
			*pw = auth.RandomPassword(20)
			defer fmt.Println("password:", *pw)
		}
		st := openStore(cfg)
		defer st.Close()
		api.Bootstrap(st)
		if _, err := api.EnsureAdmin(context.Background(), st, *user, *pw, *email); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("administrator ready:", *user)
	case "selftest":
		os.Exit(selftest(cfg))
	case "doctor": // v0.4 instx: service checks only (no API/agent needed)
		if v04Doctor() > 0 {
			os.Exit(1)
		}
	case "secrets": // v0.4 baox (secrets_cmd.go)
		os.Exit(secretsCmd(cfg, args))
	case "openapi":
		st, _ := store.Open(":memory:")
		srv := api.New(cfg, st, nil, nil, slog.Default(), version.Version)
		srv.Handler(api.RealmUser)
		srv.Handler(api.RealmAdmin)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(srv.OpenAPI())
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
}

// profileUnits returns the core units of the installed profile (from
// /etc/bpanel/agent.json), so a minimal install does not report Apache,
// PowerDNS or mail as failed (handoff-installer H-8). nil = every unit the
// agent allows (the agent filters by profile as well).
func profileUnits() []string {
	b, err := os.ReadFile("/etc/bpanel/agent.json")
	if err != nil {
		return nil
	}
	var c struct {
		Profile string `json:"profile"`
	}
	if json.Unmarshal(b, &c) != nil || c.Profile == "" {
		return nil
	}
	l, err := distro.Detect()
	if err != nil {
		return nil
	}
	return l.ProfileUnits(c.Profile)
}

func selftest(cfg api.Config) int {
	fail := 0
	check := func(name string, err error) {
		if err != nil {
			fail++
			fmt.Printf("  ✗ %-28s %v\n", name, err)
		} else {
			fmt.Printf("  ✓ %s\n", name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cl := agentrpc.NewClient(cfg.AgentSocket)
	var ping agentrpc.PingResult
	check("agent socket", cl.Call(ctx, agentrpc.MPing, agentrpc.Empty{}, &ping))
	var svc agentrpc.ServiceStatus
	err := cl.Call(ctx, agentrpc.MServiceStatus, agentrpc.ServiceStatusReq{Units: profileUnits()}, &svc)
	check("service status", err)
	for _, s := range svc.Services {
		var e error
		name := "service " + s.Unit
		if s.Active != "active" {
			if installer.SocketActive(ctx, s.Unit) {
				name += " (socket-activated)" // R2-SYS-7: Ubuntu's ssh.socket
			} else {
				e = fmt.Errorf("%s (%s)", s.Active, s.Sub)
			}
		}
		check(name, e)
	}
	st, err := store.Open(cfg.DBPath)
	check("database", err)
	if st != nil {
		st.Close()
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for _, p := range []struct {
		name string
		port int
	}{{"user panel", cfg.UserPort}, {"admin panel", cfg.AdminPort}} {
		resp, err := hc.Get(fmt.Sprintf("https://127.0.0.1:%d/api/v1/meta", p.port))
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(b), "BOZKURT") {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
		check(fmt.Sprintf("%s :%d", p.name, p.port), err)
	}
	fail += v04Doctor() // v0.4 instx
	if fail > 0 {
		fmt.Printf("\n%d check(s) failed\n", fail)
		return 1
	}
	fmt.Println("\nall checks passed")
	return 0
}

// v04Doctor prints the v0.4 service checks (rspamd, sieve, fail2ban, pdns,
// chrony, mlmmj, restic, bpanel-app@ template) and returns the number of
// required ones that are not ok. Optional ones are shown with "·".
func v04Doctor() int {
	profile := "full"
	if b, err := os.ReadFile("/etc/bpanel/agent.json"); err == nil {
		var c struct {
			Profile string `json:"profile"`
		}
		if json.Unmarshal(b, &c) == nil && c.Profile != "" {
			profile = c.Profile
		}
	}
	l, err := distro.Detect()
	if err != nil {
		fmt.Println("  ✗ distribution", err)
		return 1
	}
	out, fail := installer.FormatDoctor(installer.V04Doctor(l, profile))
	fmt.Print("\nservices (v0.4):\n" + out)
	return fail
}
