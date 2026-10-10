package agent

import (
	"context"
	"os"
	"strings"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// AliasesFile is the system aliases map (a variable for tests).
var AliasesFile = "/etc/aliases"

// AliasesWithRoot returns /etc/aliases content with "root: <email>" (the
// panel's previous root line replaced) and a postmaster alias. Shared by the
// installer (--email) and the mail.root_alias action (handoff-installer H-10).
func AliasesWithRoot(orig, email string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(orig, "\n"), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "root:") || strings.HasPrefix(t, "root ") || t == "root" || strings.HasPrefix(t, "# BOZKURT PANEL: mail for root") {
			continue
		}
		if t == "" && len(out) == 0 {
			continue
		}
		out = append(out, l)
	}
	hasPostmaster := false
	for _, l := range out {
		if strings.HasPrefix(strings.TrimSpace(l), "postmaster:") {
			hasPostmaster = true
		}
	}
	if !hasPostmaster {
		out = append(out, "postmaster: root")
	}
	out = append(out, "# BOZKURT PANEL: mail for root goes to the administrator", "root: "+email)
	return strings.Join(out, "\n") + "\n"
}

// mailRootAlias points root's mail (cron, fail2ban, unattended-upgrades) at
// the panel's contact email and rebuilds the alias database. Only a
// syntactically valid address is written (no ':' / newline / '|' injection
// into /etc/aliases).
func (a *Agent) mailRootAlias(ctx context.Context, p rpc.RootAlias) (rpc.Empty, error) {
	email := strings.TrimSpace(p.Email)
	if err := validate.Email(email); err != nil || strings.ContainsAny(email, ":|\"\\,\n\r ") {
		return rpc.Empty{}, errf("invalid_email", "%s", p.Email)
	}
	defer a.lock("aliases")()
	orig, err := os.ReadFile(AliasesFile)
	if err != nil && !os.IsNotExist(err) {
		return rpc.Empty{}, err
	}
	if err := writeAtomic(AliasesFile, []byte(AliasesWithRoot(string(orig), email)), 0o644, -1, -1); err != nil {
		return rpc.Empty{}, err
	}
	if AliasesFile != "/etc/aliases" { // tests: rebuild only the given map
		if have("postalias") {
			if _, err := run(ctx, nil, "postalias", a.mapType()+":"+AliasesFile); err != nil {
				return rpc.Empty{}, errf("newaliases_failed", "%v", err)
			}
		}
	} else if have("newaliases") {
		if _, err := run(ctx, nil, "newaliases"); err != nil {
			return rpc.Empty{}, errf("newaliases_failed", "%v", err)
		}
	}
	return rpc.Empty{}, nil
}
