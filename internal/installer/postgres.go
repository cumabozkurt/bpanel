// SPDX-License-Identifier: Apache-2.0

package installer

import (
	"context"
	"os"

	"github.com/cumabozkurt/bpanel/internal/distro"
)

// v0.4 dbx: PostgreSQL is an optional engine (PostgreSQL License, free),
// installed only with --with-postgresql. The panel reaches it through the
// agent as the postgres OS user (peer auth over the local socket); no TCP
// listener is configured beyond the distribution default (localhost).

// PostgresPackages returns the distribution packages of the PostgreSQL server and client.
func PostgresPackages(l *distro.Layout) []string {
	if l.Family == distro.Debian {
		return []string{"postgresql", "postgresql-client"}
	}
	return []string{"postgresql-server", "postgresql"}
}

// postgresSetup initialises the cluster on RHEL-family systems (Debian's
// package creates and starts one itself) and enables the service.
func (in *Installer) postgresSetup(ctx context.Context) error {
	if !in.O.PostgreSQL {
		return nil
	}
	if in.L.Family != distro.Debian {
		if _, err := os.Stat("/var/lib/pgsql/data/PG_VERSION"); err != nil {
			if err := in.sh(ctx, "postgresql-setup", "--initdb"); err != nil {
				return err
			}
		}
	}
	return in.systemctl(ctx, "enable", "--now", "postgresql")
}
