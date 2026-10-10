package shield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Result of scanning one file.
type Result struct {
	Path        string         `json:"path"`
	Name        string         `json:"name"`
	SHA256      string         `json:"sha256"`
	Size        int64          `json:"size"`
	Type        FileType       `json:"type"`
	Outcome     Outcome        `json:"outcome"`
	Detections  []Detection    `json:"detections,omitempty"`
	Engines     []EngineResult `json:"engines,omitempty"`
	Errors      []string       `json:"errors,omitempty"`
	Decision    Decision       `json:"decision"`
	Version     string         `json:"version"` // engine/ruleset versions (cache key)
	Cached      bool           `json:"cached"`
	Allowlisted bool           `json:"allowlisted,omitempty"` // sha256 marked false positive
	Rescans     int            `json:"rescans"`
	Took        time.Duration  `json:"took_ns"`
}

// Scanner orchestrates engines, cache and policy for one file.
type Scanner struct {
	Engines       []MalwareScannerProvider
	Cache         *VerdictCache
	Policy        AccountPolicy
	MaxRescans    int // re-scans when the file changes during a scan (default 3)
	Archives      ArchiveLimits
	ScanArchives  bool // run the heuristic on archive members
	EngineTimeout time.Duration
	// Allowlist (false-positive sha256 list) is consulted before cache and engines.
	Allowlist AllowChecker

	// afterEngines is a test hook run after the engines, before re-stat.
	afterEngines func(attempt int)
}

// NewScanner returns a scanner with the builtin heuristic engine plus extra.
func NewScanner(extra ...MalwareScannerProvider) *Scanner {
	return &Scanner{Engines: append([]MalwareScannerProvider{&Heuristic{}}, extra...), Cache: NewVerdictCache(),
		Policy: DefaultPolicy(), MaxRescans: 3, Archives: DefaultArchiveLimits(), ScanArchives: true, EngineTimeout: 60 * time.Second}
}

type fileID struct {
	size  int64
	mtime int64
	ino   uint64
	dev   uint64
}

func statID(p string) (fileID, os.FileInfo, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return fileID{}, nil, err
	}
	if !st.Mode().IsRegular() {
		return fileID{}, st, fmt.Errorf("not a regular file (symlinks are never followed): %s", p)
	}
	id := fileID{size: st.Size(), mtime: st.ModTime().UnixNano()}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		id.ino, id.dev = uint64(s.Ino), uint64(s.Dev)
	}
	return id, st, nil
}

// Version is the combined engine/ruleset version string.
func (s *Scanner) Version(ctx context.Context) string {
	var v []string
	for _, e := range s.Engines {
		v = append(v, e.SignatureVersion(ctx))
	}
	sort.Strings(v)
	return strings.Join(v, ";")
}

// Scan scans path; name is the logical name for extension rules (defaults to path).
func (s *Scanner) Scan(ctx context.Context, path string) (Result, error) {
	return s.ScanNamed(ctx, path, "")
}

// AllowChecker reports whether a sha256 was marked false positive for account (or globally).
type AllowChecker interface {
	Allowed(sha256, account string) bool
}

type accountCtxKey struct{}

// WithAccount tags ctx with the account a scan is for (allowlist scope).
func WithAccount(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, accountCtxKey{}, account)
}

func accountFrom(ctx context.Context) string {
	a, _ := ctx.Value(accountCtxKey{}).(string)
	return a
}

// ScanAccount scans path on behalf of account (account-scoped allowlist applies).
func (s *Scanner) ScanAccount(ctx context.Context, path, account string) (Result, error) {
	return s.ScanNamed(WithAccount(ctx, account), path, "")
}

func (s *Scanner) ScanNamed(ctx context.Context, path, name string) (Result, error) {
	start := time.Now()
	if name == "" {
		name = path
	}
	max := s.MaxRescans
	if max <= 0 {
		max = 3
	}
	var res Result
	for attempt := 0; attempt <= max; attempt++ {
		id1, _, err := statID(path)
		if err != nil {
			return Result{Path: path, Name: name}, err
		}
		res, err = s.scanOnce(ctx, path, name, id1.size)
		if err != nil {
			return res, err
		}
		if s.afterEngines != nil {
			s.afterEngines(attempt)
		}
		id2, _, err := statID(path)
		if err == nil && id2 == id1 {
			res.Rescans = attempt
			res.Decision = Decide(res.Outcome, res.Type.Class, s.Policy)
			res.Took = time.Since(start)
			return res, nil
		}
		if err != nil {
			return res, fmt.Errorf("file vanished during scan: %w", err)
		}
	}
	// never settled: no trustworthy verdict
	res.Rescans = max
	res.Outcome = worstOutcome(res.Outcome, OutUnavailable)
	res.Errors = append(res.Errors, fmt.Sprintf("file kept changing during %d scans", max+1))
	res.Decision = Decide(res.Outcome, res.Type.Class, s.Policy)
	res.Took = time.Since(start)
	return res, nil
}

func worstOutcome(a, b Outcome) Outcome {
	rank := map[Outcome]int{OutClean: 0, OutTimeout: 1, OutUnavailable: 2, OutSuspicious: 3, OutInfected: 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func (s *Scanner) scanOnce(ctx context.Context, path, name string, size int64) (Result, error) {
	res := Result{Path: path, Name: name, Size: size}
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	h := sha256.New()
	hd := make([]byte, 8192)
	n, _ := io.ReadFull(f, hd)
	hd = hd[:n]
	h.Write(hd)
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return res, err
	}
	f.Close()
	res.SHA256 = hex.EncodeToString(h.Sum(nil))
	res.Type = DetectType(hd, name)
	res.Version = s.Version(ctx)

	if s.Allowlist != nil && s.Allowlist.Allowed(res.SHA256, accountFrom(ctx)) {
		res.Outcome, res.Allowlisted = OutClean, true
		return res, nil
	}

	// name-dependent rules (double extension) make the cache key include the name class
	key := res.SHA256 + "|" + string(res.Type.Class) + "|" + strings.ToLower(name[strings.LastIndex(name, "/")+1:])
	if s.Cache != nil {
		if cv, ok := s.Cache.Get(key, res.Version); ok {
			res.Outcome, res.Detections, res.Cached = cv.Outcome, cv.Detections, true
			return res, nil
		}
	}

	out := OutClean
	failed := false
	timedOut := false
	t := Target{Path: path, Name: name, Size: size}
	for _, e := range s.Engines {
		ectx := ctx
		var cancel context.CancelFunc = func() {}
		if s.EngineTimeout > 0 {
			ectx, cancel = context.WithTimeout(ctx, s.EngineTimeout)
		}
		er, err := e.Scan(ectx, t)
		cancel()
		er.Engine = e.Name()
		if err != nil {
			er.Error = err.Error()
			failed = true
			if errors.Is(err, ErrTimeout) {
				timedOut = true
			}
			res.Errors = append(res.Errors, e.Name()+": "+err.Error())
		}
		res.Engines = append(res.Engines, er)
		res.Detections = append(res.Detections, er.Detections...)
	}
	if s.ScanArchives && res.Type.Class == ClassArchive {
		aerr := WalkArchive(path, s.Archives, func(e ArchiveEntry, data []byte) error {
			r := HeuristicResult(data, e.Name, e.Name)
			res.Detections = append(res.Detections, r.Detections...)
			return nil
		})
		if aerr != nil {
			res.Detections = append(res.Detections, Detection{Engine: "bpanel-archive", Signature: "BPANEL.Archive.Rejected",
				Verdict: Suspicious, Severity: SevHigh, Detail: aerr.Error()})
		}
	}
	for _, d := range res.Detections {
		switch d.Verdict {
		case Infected:
			out = worstOutcome(out, OutInfected)
		case Suspicious:
			out = worstOutcome(out, OutSuspicious)
		}
	}
	// fail closed: an engine that gave no answer means no clean verdict
	if out == OutClean && failed {
		out = OutUnavailable
		if timedOut {
			out = OutTimeout
		}
	}
	res.Outcome = out
	if s.Cache != nil && !failed {
		s.Cache.Put(key, res.Version, out, res.Detections)
	}
	return res, nil
}
