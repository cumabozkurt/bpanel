//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/xfer"
)

// XferDir is the mock's transfer directory (drop cpmove/BPanel archives here
// to try the Transfer Tool with `bpanel-api --dev`).
var XferDir = filepath.Join(os.TempDir(), "bpanel-mock-xfer")

var mockXferName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(tar\.gz|tgz|tar)$`)

func xferRPCErr(err error) error {
	var xe *xfer.Error
	if errors.As(err, &xe) {
		return &rpc.Error{Code: xe.Code.Error(), Message: xe.Detail}
	}
	return &rpc.Error{Code: "action_failed", Message: err.Error()}
}

// mockXfer answers xfer.* with the real parser/writer against XferDir.
// Restores are not performed (nothing is written outside XferDir); the
// remote pull is reported as unsupported in the mock.
func (m *Mock) mockXfer(method string, params any) (any, error) {
	_ = os.MkdirAll(XferDir, 0o700)
	path := func(n string) (string, error) {
		if !mockXferName.MatchString(n) {
			return "", &rpc.Error{Code: "xfer_invalid_archive", Message: "invalid archive name"}
		}
		return filepath.Join(XferDir, n), nil
	}
	switch method {
	case rpc.MXferList:
		out := rpc.XferArchiveList{Archives: []rpc.XferArchive{}, Dir: XferDir}
		ents, _ := os.ReadDir(XferDir)
		for _, e := range ents {
			if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && mockXferName.MatchString(e.Name()) {
				out.Archives = append(out.Archives, rpc.XferArchive{Name: e.Name(), Bytes: fi.Size(), ModTime: fi.ModTime().Unix()})
			}
		}
		sort.Slice(out.Archives, func(i, j int) bool { return out.Archives[i].ModTime > out.Archives[j].ModTime })
		return out, nil
	case rpc.MXferAnalyse:
		var p rpc.XferArchiveRef
		conv(params, &p)
		ap, err := path(p.Archive)
		if err != nil {
			return nil, err
		}
		md, err := xfer.Analyse(ap, xfer.DefaultLimits)
		if err != nil {
			return nil, xferRPCErr(err)
		}
		return rpc.XferAnalyseResult{Model: *md}, nil
	case rpc.MXferDelete:
		var p rpc.XferArchiveRef
		conv(params, &p)
		ap, err := path(p.Archive)
		if err != nil {
			return nil, err
		}
		_ = os.Remove(ap)
		return rpc.Empty{}, nil
	case rpc.MXferFetch:
		return nil, &rpc.Error{Code: "unsupported", Message: "the mock agent does not connect to remote hosts"}
	case rpc.MXferRestoreHome, rpc.MXferRestoreDB:
		return rpc.XferRestoreResult{}, nil
	case rpc.MXferExport:
		var p rpc.XferExport
		conv(params, &p)
		ap, err := path(p.Archive)
		if err != nil {
			return nil, err
		}
		var man xfer.Manifest
		_ = json.Unmarshal(p.Manifest, &man)
		f, err := os.Create(ap)
		if err != nil {
			return nil, xferRPCErr(err)
		}
		defer f.Close()
		gz := gzip.NewWriter(f)
		w := xfer.NewWriter(gz)
		for _, d := range p.Databases {
			_ = w.AddBytes("mysql/"+d+".sql", []byte("-- mock dump\n"))
		}
		for _, b := range p.Blobs {
			_ = w.AddBytes(b.Name, []byte(b.Content))
		}
		if err := w.Close(man); err != nil {
			return nil, xferRPCErr(err)
		}
		gz.Close()
		return rpc.XferExportResult{Archive: p.Archive, Files: len(p.Databases) + len(p.Blobs)}, nil
	}
	return nil, &rpc.Error{Code: "unknown_method", Message: method}
}
