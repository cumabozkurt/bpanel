// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Cron cage: an account's cron jobs run inside its slice (bpanel-u-<user>.slice)
// so they share the account's CPU/memory/pids limits with PHP-FPM.
//
// The user's command text is never placed on a root-owned command line. The
// agent stores it as a script file (CronScriptPath, root-owned 0644) and the
// /etc/cron.d entry is a fixed argv built only from validated tokens:
// systemd-run ... --uid=<uid> --gid=<gid> -- /bin/sh <script>. The only
// interpreter of user input is /bin/sh running *as that user*, which is what
// a crontab line is.

// CronRoot holds the per-account job scripts.
const CronRoot = "/var/lib/bpanel/cron"

// CageExecBin + "cage-exec" is the no-systemd fallback (CageExec): it joins
// the account cgroup, drops to uid/gid with no_new_privs and execs argv.
const CageExecBin = "/usr/local/bin/bpanel-agent"

var (
	cronFieldRe = regexp.MustCompile(`^[0-9A-Za-z*/,\-]{1,64}$`)
	cronMacroRe = regexp.MustCompile(`^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$`)
	jobIDRe     = regexp.MustCompile(`^[0-9]{1,12}$`)
	safeTokRe   = regexp.MustCompile(`^[A-Za-z0-9_./=:@+-]+$`)
)

// CronJob is one account crontab entry.
type CronJob struct {
	ID       string // numeric job id from the panel DB
	Schedule string // 5 fields or an @macro
	Command  string // the user's own command line
}

// Validate refuses schedules that could smuggle extra cron fields and
// commands with NUL/newlines (a newline would start a second cron.d entry).
func (j CronJob) Validate() error {
	if !jobIDRe.MatchString(j.ID) {
		return fmt.Errorf("invalid job id")
	}
	f := strings.Fields(j.Schedule)
	switch {
	case len(f) == 1 && cronMacroRe.MatchString(f[0]):
	case len(f) == 5:
		for _, x := range f {
			if !cronFieldRe.MatchString(x) {
				return fmt.Errorf("invalid schedule field %q", x)
			}
		}
	default:
		return fmt.Errorf("schedule must be 5 fields or an @macro")
	}
	if strings.TrimSpace(j.Command) == "" || len(j.Command) > 4096 || strings.ContainsAny(j.Command, "\x00\r\n") {
		return fmt.Errorf("command must be one non-empty line (max 4096 bytes)")
	}
	return nil
}

// CronScriptPath is where job id of user is stored.
func CronScriptPath(user, id string) string {
	return filepath.Join(CronRoot, user, id+".sh")
}

// RenderCronScript is the job script body (executed by /bin/sh as the user).
func RenderCronScript(j CronJob) string {
	return "# bpanel cron job " + j.ID + " (managed; edit in the panel)\n" + j.Command + "\n"
}

// CronCommandArgv builds the argv that runs one job inside the account's
// slice. systemd=true uses a transient unit (limits enforced by systemd);
// otherwise the cage-exec helper joins cgroupDir itself.
func CronCommandArgv(user string, uid, gid int, id string, systemd bool, cgroupRoot string) ([]string, error) {
	if !UserRe.MatchString(user) {
		return nil, fmt.Errorf("invalid user")
	}
	if uid < 1000 || gid < 1000 {
		return nil, fmt.Errorf("refusing system uid/gid %d/%d", uid, gid)
	}
	if !jobIDRe.MatchString(id) {
		return nil, fmt.Errorf("invalid job id")
	}
	script := CronScriptPath(user, id)
	if systemd {
		return []string{"/usr/bin/systemd-run", "--quiet", "--collect", "--wait",
			"--slice=" + SliceName(user),
			"--unit=bpanel-cron-" + user + "-" + id,
			"--uid=" + strconv.Itoa(uid), "--gid=" + strconv.Itoa(gid),
			"--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes",
			"--working-directory=/home/" + user,
			"--", "/bin/sh", script}, nil
	}
	return []string{CageExecBin, "cage-exec", "--cgroup", CgroupDir(cgroupRoot, user),
		"--uid", strconv.Itoa(uid), "--gid", strconv.Itoa(gid),
		"--chdir", "/home/" + user, "--", "/bin/sh", script}, nil
}

// RenderCronD renders /etc/cron.d/bpanel-<user>: one root entry per job, all
// command tokens matching a no-metacharacter allowlist (cron hands the
// command to sh, so this keeps it a plain word list; '%' is refused because
// cron turns it into a newline).
func RenderCronD(user string, uid, gid int, jobs []CronJob, systemd bool, cgroupRoot string) (string, error) {
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL. Account " + user + ". Do not edit.\n")
	b.WriteString("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nMAILTO=\"\"\n")
	for _, j := range jobs {
		if err := j.Validate(); err != nil {
			return "", fmt.Errorf("job %s: %w", j.ID, err)
		}
		argv, err := CronCommandArgv(user, uid, gid, j.ID, systemd, cgroupRoot)
		if err != nil {
			return "", err
		}
		for _, t := range argv {
			if !safeTokRe.MatchString(t) {
				return "", fmt.Errorf("unsafe token %q", t)
			}
		}
		fmt.Fprintf(&b, "%s root %s\n", strings.Join(strings.Fields(j.Schedule), " "), strings.Join(argv, " "))
	}
	return b.String(), nil
}
