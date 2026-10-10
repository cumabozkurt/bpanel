package shield

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// BuiltinYaraRules is rules/bpanel.yar, embedded.
//
//go:embed rules/bpanel.yar
var BuiltinYaraRules []byte

// Yara drives the `yara` command-line tool (BSD-3-Clause, separate
// program). Arguments are passed as argv (no shell); the file path is made
// absolute so it can never be read as an option.
type Yara struct {
	Bin      string // default "yara" looked up in PATH
	Rules    string // rules file; WriteBuiltinRules creates one
	Timeout  time.Duration
	Disabled bool
}

func NewYara(rules string) *Yara { return &Yara{Bin: "yara", Rules: rules, Timeout: 30 * time.Second} }

// WriteBuiltinRules writes the embedded rules into dir and returns the path.
func WriteBuiltinRules(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "bpanel.yar")
	return p, os.WriteFile(p, BuiltinYaraRules, 0o640)
}

func (y *Yara) Name() string { return "yara" }
func (y *Yara) Kind() string { return KindExternal }

func (y *Yara) bin() (string, error) {
	b := y.Bin
	if b == "" {
		b = "yara"
	}
	p, err := exec.LookPath(b)
	if err != nil {
		return "", fmt.Errorf("%w: yara binary not found (%v)", ErrUnavailable, err)
	}
	return p, nil
}

func (y *Yara) version(ctx context.Context) (string, error) {
	b, err := y.bin()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, b, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%w: yara --version: %v", ErrUnavailable, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (y *Yara) rulesHash() string {
	b, err := os.ReadFile(y.Rules)
	if err != nil {
		return "norules"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:6])
}

func (y *Yara) Available(ctx context.Context) bool {
	if y.Disabled {
		return false
	}
	_, err := y.version(ctx)
	return err == nil
}

func (y *Yara) SignatureVersion(ctx context.Context) string {
	v, err := y.version(ctx)
	if err != nil {
		return "yara:unavailable"
	}
	return "yara:" + v + "/" + y.rulesHash()
}

func (y *Yara) Status(ctx context.Context) ProviderStatus {
	st := ProviderStatus{Name: y.Name(), Kind: y.Kind(), License: "BSD-3-Clause (separate program)", RealTime: true, OnDemand: true, CheckedUnix: time.Now().Unix()}
	if y.Disabled {
		st.Status, st.Reason = StatusDisabled, "disabled in the Shield settings"
		return st
	}
	if _, err := y.bin(); err != nil {
		st.Status, st.Reason = StatusNotInstalled, "yara is not installed (apt install yara)"
		return st
	}
	v, err := y.version(ctx)
	if err != nil {
		st.Status, st.Reason = StatusUnavailable, err.Error()
		return st
	}
	if _, err := os.Stat(y.Rules); err != nil {
		st.Status, st.Reason, st.Version = StatusNotConfigured, "rules file missing: "+y.Rules, v
		return st
	}
	st.Status, st.Version, st.SigVersion = StatusOK, v, y.rulesHash()
	return st
}

var reYaraMeta = regexp.MustCompile(`(\w+)="((?:[^"\\]|\\.)*)"`)

// ParseYaraOutput parses `yara -m` lines: RULE [k="v",...] PATH
func ParseYaraOutput(out []byte, entry string) []Detection {
	var dets []Detection
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "warning") || strings.HasPrefix(line, "error") {
			continue
		}
		rule, rest, _ := strings.Cut(line, " ")
		d := Detection{Engine: "yara", Signature: rule, Verdict: Suspicious, Severity: SevMedium, Entry: entry}
		if strings.HasPrefix(rest, "[") {
			if i := strings.Index(rest, "] "); i > 0 {
				for _, m := range reYaraMeta.FindAllStringSubmatch(rest[1:i], -1) {
					switch m[1] {
					case "verdict":
						if m[2] == string(Infected) {
							d.Verdict = Infected
						}
					case "severity":
						d.Severity = m[2]
					case "description":
						d.Detail = m[2]
					}
				}
			}
		}
		dets = append(dets, d)
	}
	return dets
}

func (y *Yara) Scan(ctx context.Context, t Target) (EngineResult, error) {
	start := time.Now()
	res := EngineResult{Engine: y.Name()}
	if y.Disabled {
		return res, fmt.Errorf("%w: disabled", ErrUnavailable)
	}
	b, err := y.bin()
	if err != nil {
		return res, err
	}
	abs, err := filepath.Abs(t.Path)
	if err != nil {
		return res, err
	}
	to := y.Timeout
	if to <= 0 {
		to = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	secs := int(to.Seconds())
	if secs < 1 {
		secs = 1
	}
	cmd := exec.CommandContext(ctx, b, "-w", "-m", "-a", fmt.Sprint(secs), "--", y.Rules, abs)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return res, ErrTimeout
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return res, fmt.Errorf("%w: yara exited %d: %s", ErrUnavailable, ee.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return res, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	res.Verdict = Clean
	res.Detections = ParseYaraOutput(stdout.Bytes(), "")
	for _, d := range res.Detections {
		res.Verdict = worst(res.Verdict, d.Verdict)
	}
	res.Took = time.Since(start)
	return res, nil
}
