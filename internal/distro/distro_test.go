package distro

import (
	"strings"
	"testing"
)

// SYS (PHP install): PHP 8.5 ships OPcache built in; no *-opcache package exists.
func TestPHPPackagesOpcache(t *testing.T) {
	for _, rel := range []map[string]string{{"ID": "ubuntu", "VERSION_ID": "24.04"}, {"ID": "debian", "VERSION_ID": "13"}, {"ID": "almalinux", "VERSION_ID": "9.6"}} {
		l, err := ForRelease(rel)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range KnownPHP {
			pk := strings.Join(l.PHPPackages(v), " ")
			has := strings.Contains(pk, "opcache")
			if want := v != "8.5"; has != want {
				t.Errorf("%s PHP %s: opcache present=%v want %v (%s)", rel["ID"], v, has, want, pk)
			}
			if !strings.Contains(pk, "fpm") {
				t.Errorf("%s PHP %s: no fpm package", rel["ID"], v)
			}
		}
	}
	if phpAtLeast("8.10", 8, 5) != true || phpAtLeast("8.4", 8, 5) || phpAtLeast("x", 8, 5) {
		t.Fatal("phpAtLeast")
	}
}
