package installer

import (
	"fmt"
	"strings"
	"testing"
)

// handoff-backend I-2: ":fail:" forwarders are rejected before any permit.
func TestPostfixRejectMapFirst(t *testing.T) {
	for _, s := range PostfixSettings("h.test", "hash", "/etc/postfix/bpanel", "c", "k") {
		if v, ok := strings.CutPrefix(s, "smtpd_recipient_restrictions="); ok {
			parts := strings.Split(v, ",")
			if parts[0] != "check_recipient_access hash:/etc/postfix/bpanel/vreject" {
				t.Fatalf("vreject not first: %s", v)
			}
			if parts[len(parts)-1] != "reject_unauth_destination" {
				t.Fatalf("open relay risk: %s", v)
			}
			return
		}
	}
	t.Fatal("no smtpd_recipient_restrictions")
}

// handoff-backend I-1 / I-5 / SEC-3: agent state directories and /home.
func TestDirsV02(t *testing.T) {
	want := map[string]string{"/etc/bpanel/accounts": "0700 root:root", "/etc/bpanel/owners": "0700 root:root",
		"/etc/bpanel/restic": "0700 root:root", "/var/lib/bpanel/restore": "0711 root:root", "/home": "0711 root:root"}
	for _, prof := range []string{"minimal", "web", "full"} {
		got := map[string]string{}
		for _, d := range Dirs(ubuntu(t), prof) {
			got[d.Path] = fmt.Sprintf("%04o %s", uint32(d.Mode.Perm()), d.Owner)
		}
		for p, w := range want {
			if got[p] != w {
				t.Errorf("%s %s: %q want %q", prof, p, got[p], w)
			}
		}
	}
}

// handoff-backend I-4a: cron jobs land in the user slice.
func TestCronPAMWithSystemd(t *testing.T) {
	orig := "@include common-auth\nsession required pam_env.so\n@include common-session-noninteractive"
	got := CronPAMWithSystemd(orig)
	if !strings.Contains(got, "session    optional   pam_systemd.so") || !strings.HasPrefix(got, orig+"\n") {
		t.Fatalf("got:\n%s", got)
	}
	if CronPAMWithSystemd(got) != got {
		t.Fatal("not idempotent")
	}
	commented := "# session optional pam_systemd.so\n"
	if !strings.Contains(CronPAMWithSystemd(commented), "\nsession    optional   pam_systemd.so") {
		t.Fatal("a commented line must not count")
	}
}

// handoff-backend I-4b: every FPM master runs in bpanel-php.slice.
func TestPHPSlice(t *testing.T) {
	if !strings.Contains(PHPFPMDropIn, "Slice=bpanel-php.slice") || !strings.Contains(UnitPHPSlice, "[Slice]") {
		t.Fatal("php slice missing")
	}
	m := Render(ubuntu(t), RenderOpts{Profile: "minimal", Hostname: "h.test"})
	if m["/etc/systemd/system/bpanel-php.slice"] != UnitPHPSlice {
		t.Fatal("slice not rendered")
	}
}
