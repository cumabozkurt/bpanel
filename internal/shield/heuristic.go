package shield

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"
	"time"
)

// HeuristicVersion is bumped whenever a rule changes (part of the cache key).
const HeuristicVersion = "bpanel-heur:2026.10.1"

// HeurRule is one native detection rule.
type HeurRule struct {
	ID       string
	Verdict  Verdict // Suspicious or Infected
	Severity string
	Desc     string
	Match    func(data []byte, name string, ft FileType) bool
}

func reRule(re string) func([]byte, string, FileType) bool {
	r := regexp.MustCompile(re)
	return func(d []byte, _ string, _ FileType) bool { return r.Match(d) }
}

var (
	reTaintAssign = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:@\s*)?(?:trim\s*\(\s*|base64_decode\s*\(\s*|urldecode\s*\(\s*|stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b`)
	reExecDirect  = regexp.MustCompile(`(?i)\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*[^;]{0,60}?\$_(?:GET|POST|REQUEST|COOKIE)\b`)
	reBase64Run   = regexp.MustCompile(`[A-Za-z0-9+/]{256,}={0,2}`)
	reDoubleExt   = regexp.MustCompile(`(?i)\.(?:php[0-9]?|phtml|phar|pht|pl|py|cgi|sh|asp|aspx|jsp)\.[a-z0-9]{1,5}$`)
	webshellMarks = []string{"c99shell", "c99_buff_prepare", "c99sh_", "r57shell", "r57_pwd", "wso_version", "WSO 2.", "WSO 4.", "b374k", "FilesMan", "Web Shell by oRb", "Uname:</td>"}
)

// HeuristicRules is the native rule set.
var HeuristicRules = []HeurRule{
	{ID: "eicar_test", Verdict: Infected, Severity: SevCritical, Desc: "EICAR antivirus test string",
		Match: func(d []byte, _ string, _ FileType) bool { return bytes.Contains(d, []byte(EICAR)) }},
	{ID: "php_eval_decode", Verdict: Infected, Severity: SevHigh, Desc: "eval/assert of decoded payload (base64/gzinflate/rot13 chain)",
		Match: reRule(`(?i)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin)\s*\(`)},
	{ID: "php_decode_chain", Verdict: Suspicious, Severity: SevMedium, Desc: "nested decoder chain (e.g. gzinflate(base64_decode(...)))",
		Match: reRule(`(?i)\b(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(\s*(?:base64_decode|str_rot13|gzinflate|strrev)\s*\(`)},
	{ID: "php_assert_input", Verdict: Infected, Severity: SevHigh, Desc: "assert()/create_function on request input",
		Match: reRule(`(?i)\b(?:assert|create_function)\s*\([^;]{0,40}\$_(?:GET|POST|REQUEST|COOKIE)\b`)},
	{ID: "php_preg_replace_e", Verdict: Infected, Severity: SevHigh, Desc: "preg_replace with /e (code execution) modifier",
		Match: reRule(`(?i)preg_replace\s*\(\s*['"](?:/[^/'"]*/|#[^#'"]*#|~[^~'"]*~|\|[^|'"]*\|)[a-z]*e[a-z]*['"]\s*,`)},
	{ID: "php_input_exec", Verdict: Infected, Severity: SevCritical, Desc: "request input flows into a command execution function",
		Match: func(d []byte, _ string, _ FileType) bool {
			if reExecDirect.Match(d) {
				return true
			}
			for _, m := range reTaintAssign.FindAllSubmatch(d, 32) {
				v := regexp.QuoteMeta(string(m[1]))
				if regexp.MustCompile(`(?i)\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*[^;]{0,40}?\$` + v + `\b`).Match(d) {
					return true
				}
			}
			return false
		}},
	{ID: "php_input_callable", Verdict: Infected, Severity: SevHigh, Desc: "request input used as a function name",
		Match: reRule(`\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(`)},
	{ID: "php_backtick_input", Verdict: Infected, Severity: SevHigh, Desc: "shell backticks around request input",
		Match: reRule("`[^`]{0,40}\\$_(?:GET|POST|REQUEST|COOKIE)\\b[^`]*`")},
	{ID: "webshell_marker", Verdict: Infected, Severity: SevCritical, Desc: "known web shell marker (c99/r57/WSO/b374k/FilesMan)",
		Match: func(d []byte, _ string, _ FileType) bool {
			for _, m := range webshellMarks {
				if bytes.Contains(d, []byte(m)) {
					return true
				}
			}
			return false
		}},
	{ID: "long_base64_entropy", Verdict: Suspicious, Severity: SevMedium, Desc: "long high-entropy base64 blob in a script",
		Match: func(d []byte, _ string, ft FileType) bool {
			if ft.Class != ClassScript {
				return false
			}
			for _, m := range reBase64Run.FindAll(d, 64) {
				if len(m) >= 1024 && ShannonEntropy(m) >= 5.0 {
					return true
				}
			}
			return false
		}},
	{ID: "php_in_image", Verdict: Infected, Severity: SevHigh, Desc: "PHP code inside an image file",
		Match: func(d []byte, name string, ft FileType) bool {
			isImg := IsImageName(name) || ft.Kind == "png" || ft.Kind == "jpeg" || ft.Kind == "gif" || (ft.Disguised && ft.ExtKind != "script")
			return isImg && !strings.HasSuffix(strings.ToLower(name), ".svg") && ContainsPHPTag(d)
		}},
	{ID: "double_extension", Verdict: Suspicious, Severity: SevMedium, Desc: "double extension hiding a script (x.php.jpg)",
		Match: func(_ []byte, name string, _ FileType) bool { return reDoubleExt.MatchString(name) }},
	{ID: "php_chr_concat", Verdict: Suspicious, Severity: SevMedium, Desc: "chr() concatenation obfuscation",
		Match: reRule(`(?i)(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){8,}`)},
}

// ShannonEntropy in bits per byte.
func ShannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var f [256]int
	for _, c := range b {
		f[c]++
	}
	e := 0.0
	n := float64(len(b))
	for _, c := range f {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// MatchHeuristics returns the ids of the rules that match.
func MatchHeuristics(data []byte, name string) []string {
	ft := DetectType(head(data), name)
	var ids []string
	for _, r := range HeuristicRules {
		if r.Match(data, name, ft) {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func head(b []byte) []byte {
	if len(b) > 8192 {
		return b[:8192]
	}
	return b
}

func heurRule(id string) HeurRule {
	for _, r := range HeuristicRules {
		if r.ID == id {
			return r
		}
	}
	return HeurRule{ID: id, Verdict: Suspicious, Severity: SevMedium}
}

// HeuristicResult turns matched ids into an EngineResult.
func HeuristicResult(data []byte, name, entry string) EngineResult {
	res := EngineResult{Engine: "bpanel-heuristic", Version: HeuristicVersion, Verdict: Clean}
	for _, id := range MatchHeuristics(data, name) {
		r := heurRule(id)
		res.Verdict = worst(res.Verdict, r.Verdict)
		res.Detections = append(res.Detections, Detection{Engine: res.Engine, Signature: "BPANEL.Heur." + id, Verdict: r.Verdict, Severity: r.Severity, Detail: r.Desc, Entry: entry})
	}
	return res
}

// Heuristic is the always-available native provider.
type Heuristic struct {
	MaxBytes int64 // bytes read per file (default 16 MiB); the rest is not inspected
}

func (h *Heuristic) Name() string                            { return "bpanel-heuristic" }
func (h *Heuristic) Kind() string                            { return KindBuiltin }
func (h *Heuristic) Available(context.Context) bool          { return true }
func (h *Heuristic) SignatureVersion(context.Context) string { return HeuristicVersion }
func (h *Heuristic) Status(context.Context) ProviderStatus {
	return ProviderStatus{Name: h.Name(), Kind: KindBuiltin, License: "BPANEL", Status: StatusOK, Version: HeuristicVersion,
		SigVersion: HeuristicVersion, RealTime: true, OnDemand: true, CheckedUnix: time.Now().Unix()}
}

func (h *Heuristic) Scan(ctx context.Context, t Target) (EngineResult, error) {
	start := time.Now()
	max := h.MaxBytes
	if max <= 0 {
		max = 16 << 20
	}
	f, err := os.Open(t.Path)
	if err != nil {
		return EngineResult{Engine: h.Name()}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return EngineResult{Engine: h.Name()}, err
	}
	if ctx.Err() != nil {
		return EngineResult{Engine: h.Name()}, ErrTimeout
	}
	name := t.Name
	if name == "" {
		name = t.Path
	}
	res := HeuristicResult(data, name, "")
	if int64(len(data)) == max {
		res.Error = fmt.Sprintf("only the first %d bytes were inspected", max)
	}
	res.Took = time.Since(start)
	return res, nil
}
