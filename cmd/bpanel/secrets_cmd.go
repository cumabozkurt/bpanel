package main

// v0.4 baox: `bpanel secrets status` and `bpanel secrets migrate --to X`.
// Output names secrets only, never values.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cumabozkurt/bpanel/internal/api"
	"github.com/cumabozkurt/bpanel/internal/redact"
)

func secretsCmd(cfg api.Config, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: bpanel secrets status | migrate --to openbao|local")
		return 2
	}
	st := openStore(cfg)
	defer st.Close()
	switch args[0] {
	case "status":
		p := api.SecretsProviderName(cfg, st)
		ss, err := api.OpenSecretStore(cfg, st, p)
		out := map[string]any{"provider": p}
		if err != nil {
			out["status"] = "unavailable"
			out["reason"] = redact.String(err.Error())
		} else {
			out["store"] = ss.Status()
		}
		if cfg.Secrets.Provider != "" {
			out["pinned_by_config"] = true
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	case "migrate":
		fs := flag.NewFlagSet("secrets migrate", flag.ExitOnError)
		to := fs.String("to", "", "destination provider: openbao or local")
		fs.Parse(args[1:])
		if *to != "openbao" && *to != "local" {
			fmt.Fprintln(os.Stderr, "--to must be openbao or local")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		res, from, err := api.MigrateSecrets(ctx, cfg, st, *to)
		fmt.Printf("from=%s to=%s copied=%d verified=%d\n", from, *to, res.Copied, res.Verified)
		for _, n := range res.Failed {
			fmt.Println("  failed:", n)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "migration NOT switched:", redact.String(err.Error()))
			return 1
		}
		fmt.Printf("switched: setting %s=%s (restart bpanel-api to apply)\n", api.SettingSecretsProvider, *to)
		if cfg.Secrets.Provider != "" && cfg.Secrets.Provider != *to {
			fmt.Fprintf(os.Stderr, "warning: api.json pins secrets.provider=%s; edit it to %s or remove it\n", cfg.Secrets.Provider, *to)
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "unknown secrets subcommand")
	return 2
}
