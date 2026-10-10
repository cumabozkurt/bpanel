package rbac

import (
	"strings"
	"testing"
)

func TestEffectiveCompat(t *testing.T) {
	cases := map[[2]string]string{
		{"admin", ""}: SuperAdmin, {"admin", "auditor"}: Auditor, {"admin", "bogus"}: Auditor,
		{"reseller", ""}: Reseller, {"user", ""}: User, {"user", "super_admin"}: User, {"x", ""}: "",
	}
	for in, want := range cases {
		if got := Effective(in[0], in[1]); got != want {
			t.Errorf("Effective(%q,%q)=%q want %q", in[0], in[1], got, want)
		}
	}
}

func TestAuditorReadOnly(t *testing.T) {
	for p := range Catalogue {
		if Has(Auditor, p) && !strings.HasSuffix(p, ".read") && p != TokensSelf {
			t.Errorf("auditor has mutating perm %s", p)
		}
	}
	if !Has(Auditor, AuditRead) {
		t.Fatal("auditor must read audit")
	}
}

func TestRolePermsAreCatalogued(t *testing.T) {
	for role, ps := range rolePerms {
		for p := range ps {
			if !Known(p) {
				t.Errorf("%s: unknown perm %s", role, p)
			}
		}
	}
	if !Has(SuperAdmin, FirewallWrite) || Has(SuperAdmin, "nope.x") {
		t.Fatal("super admin")
	}
	if Has(Reseller, ServerWrite) || Has(Technical, AccountsTerminate) || Has(Technical, AccountsCreate) || Has(User, AccountsRead) {
		t.Fatal("over-privileged role")
	}
}
