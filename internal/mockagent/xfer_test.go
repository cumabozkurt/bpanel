//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/xfer"
)

func TestMockXferExportAnalyse(t *testing.T) {
	old := XferDir
	XferDir = t.TempDir()
	t.Cleanup(func() { XferDir = old })
	m := New(t.TempDir())
	ctx := context.Background()
	man, _ := json.Marshal(xfer.Manifest{Account: xfer.Account{Username: "demo", MainDomain: "demo.test"}, Domains: []xfer.Domain{{Name: "demo.test", Kind: "main"}}})
	var ex rpc.XferExportResult
	if err := m.Call(ctx, rpc.MXferExport, rpc.XferExport{User: "demo", Archive: "demo.tar.gz", Databases: []string{"demo_db"}, Manifest: man}, &ex); err != nil {
		t.Fatal(err)
	}
	var an rpc.XferAnalyseResult
	if err := m.Call(ctx, rpc.MXferAnalyse, rpc.XferArchiveRef{Archive: "demo.tar.gz"}, &an); err != nil || an.Model.Account.Username != "demo" || an.Model.Format != "bpanel" {
		t.Fatalf("%+v %v", an.Model, err)
	}
	var re *rpc.Error
	if err := m.Call(ctx, rpc.MXferAnalyse, rpc.XferArchiveRef{Archive: "../x.tar.gz"}, &an); !errors.As(err, &re) || re.Code != "xfer_invalid_archive" {
		t.Fatal(err)
	}
	if err := m.Call(ctx, rpc.MXferFetch, rpc.XferFetch{}, &rpc.XferFetchResult{}); !errors.As(err, &re) || re.Code != "unsupported" {
		t.Fatal(err)
	}
}
