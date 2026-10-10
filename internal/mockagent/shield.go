//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

// Dev-mode answers for shield.* so `bpanel-api --dev` uploads work. Nothing is
// scanned: a staged file is "clean" unless its name contains "eicar" (then it
// is blocked as infected and never placed). status reports the mock engine
// honestly as "mock"; quarantine and events are always empty.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/shield"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

var (
	stageMu sync.Mutex
	staged  = map[string][]byte{} // user|id -> bytes
)

const mockMaxStage = 512 << 20

func (m *Mock) mockShield(method string, params any) (any, error) {
	switch method {
	case rpc.MShieldStageChunk:
		var p rpc.ShieldStageChunk
		conv(params, &p)
		if validate.Username(p.User) != nil || p.ID == "" {
			return nil, &rpc.Error{Code: "bad_params"}
		}
		b, err := base64.StdEncoding.DecodeString(p.Content)
		if err != nil {
			return nil, &rpc.Error{Code: "bad_chunk"}
		}
		stageMu.Lock()
		defer stageMu.Unlock()
		k := p.User + "|" + p.ID
		cur := staged[k]
		if int64(len(cur)) != p.Offset || len(cur)+len(b) > mockMaxStage {
			return nil, &rpc.Error{Code: "bad_upload_offset"}
		}
		staged[k] = append(cur, b...)
		return rpc.Empty{}, nil
	case rpc.MShieldStageAbort:
		var p rpc.ShieldStageRef
		conv(params, &p)
		stageMu.Lock()
		delete(staged, p.User+"|"+p.ID)
		stageMu.Unlock()
		return rpc.Empty{}, nil
	case rpc.MShieldStageCommit:
		var p rpc.ShieldStageCommit
		conv(params, &p)
		if validate.Username(p.User) != nil {
			return nil, &rpc.Error{Code: "invalid_username"}
		}
		stageMu.Lock()
		data, ok := staged[p.User+"|"+p.ID]
		delete(staged, p.User+"|"+p.ID)
		stageMu.Unlock()
		if !ok {
			return nil, &rpc.Error{Code: "not_found", Message: "staging file"}
		}
		name := p.Name
		if name == "" {
			name = filepath.Base(p.Path)
		}
		if strings.Contains(strings.ToLower(name), "eicar") {
			return rpc.ShieldStageCommitResult{Action: string(shield.ActBlock), Outcome: string(shield.OutInfected), Class: "other",
				Reason:     "infected (mock agent: name contains eicar)",
				Detections: []shield.Detection{{Engine: "mock", Signature: "Mock.EICAR-Test-Signature", Verdict: shield.Infected, Severity: "high"}}}, nil
		}
		home := m.home(p.User)
		if err := os.MkdirAll(home, 0o755); err != nil {
			return nil, err
		}
		root, err := os.OpenRoot(home) // refuses ../ and symlink escapes
		if err != nil {
			return nil, err
		}
		defer root.Close()
		rel := filepath.Clean(strings.TrimLeft(p.Path, "/"))
		if rel == "." || strings.HasPrefix(rel, "..") {
			return nil, &rpc.Error{Code: "invalid_path", Message: p.Path}
		}
		f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, &rpc.Error{Code: "invalid_path", Message: p.Path}
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, werr
		}
		return rpc.ShieldStageCommitResult{Placed: true, Action: string(shield.ActAllow), Outcome: string(shield.OutClean), Class: "other",
			Reason: "clean (mock agent: nothing scanned)"}, nil
	case rpc.MShieldStatus:
		return rpc.ShieldStatusResult{Engines: []shield.ProviderStatus{{Name: "mock", Kind: "mock", Status: "mock",
			Reason: "dev mock agent: files are not scanned"}}, Version: "mock", Realtime: "unsupported",
			Reason: "dev mock agent", FanReason: "dev mock agent"}, nil
	case rpc.MShieldQList:
		return rpc.ShieldQListResult{Items: []shield.QuarantineMeta{}}, nil
	case rpc.MShieldEvents:
		var p rpc.ShieldEventsReq
		conv(params, &p)
		return rpc.ShieldEventsResult{Events: []rpc.ShieldEvent{}, LastSeq: p.Since}, nil
	case rpc.MShieldScan:
		var p rpc.ShieldScanReq
		conv(params, &p)
		out := shield.OutClean
		if strings.Contains(strings.ToLower(p.Path), "eicar") {
			out = shield.OutInfected
		}
		return rpc.ShieldScanResult{Result: shield.Result{Outcome: out}}, nil
	}
	// restore/delete/falsepositive: quarantine is always empty in dev mode
	return nil, &rpc.Error{Code: "not_found", Message: "quarantine item"}
}
