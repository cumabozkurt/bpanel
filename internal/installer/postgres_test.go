// SPDX-License-Identifier: Apache-2.0

package installer

import (
	"strings"
	"testing"
)

func TestPostgresPackagesOptional(t *testing.T) {
	u := ubuntu(t)
	if strings.Contains(strings.Join(PackageList(u, "full", nil), " "), "postgresql") {
		t.Error("PostgreSQL must not be in any default profile")
	}
	if got := strings.Join(PostgresPackages(u), " "); got != "postgresql postgresql-client" {
		t.Errorf("debian: %s", got)
	}
}
