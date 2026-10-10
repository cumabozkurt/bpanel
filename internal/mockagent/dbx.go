//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"strings"
	"sync"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// PGInstalled makes the mock report PostgreSQL as installed (false = not_installed).
var PGInstalled = true

var mockPG = struct {
	sync.Mutex
	dbs map[string]bool
}{dbs: map[string]bool{}}

func ownedBy(owner, name string) bool {
	return validate.Username(owner) == nil && strings.HasPrefix(name, owner+"_")
}

// mockDbx answers the v0.4 dbx/pg methods with the real agent's contracts
// (prefix checks, not_installed), keeping PostgreSQL databases in memory.
func (m *Mock) mockDbx(method string, params any) (any, error) {
	switch method {
	case rpc.MDBXRemoteSync:
		var p rpc.DBXRemoteSync
		conv(params, &p)
		res := rpc.DBXRemoteResult{Created: []string{}, Dropped: []string{}, Skipped: []string{}}
		for _, h := range p.Hosts {
			mh, err := validate.RemoteDBHost(h)
			if err != nil {
				return nil, &rpc.Error{Code: "invalid_remote_host", Message: h}
			}
			for _, u := range p.Users {
				if !ownedBy(p.Owner, u.User) {
					return nil, &rpc.Error{Code: "invalid_db_user", Message: u.User}
				}
				res.Created = append(res.Created, u.User+"@"+mh)
			}
		}
		return res, nil
	case rpc.MDBXProcessList:
		var p rpc.DBXProcReq
		conv(params, &p)
		pg := rpc.DBXEngineStatus{Status: "ok"}
		if !PGInstalled {
			pg.Status = "not_installed"
		}
		return rpc.DBXProcList{MariaDB: rpc.DBXEngineStatus{Status: "ok"}, PostgreSQL: pg, Processes: []rpc.DBXProcess{
			{Engine: "mariadb", ID: 4242, User: p.Owner + "_app", Host: "localhost", DB: p.Owner + "_app", Command: "Query", State: "Sending data", Seconds: 37, Query: "SELECT SLEEP(60)"},
		}}, nil
	case rpc.MDBXKill:
		var p rpc.DBXKill
		conv(params, &p)
		if p.ID != 4242 {
			return nil, &rpc.Error{Code: "not_found", Message: "no such query"}
		}
		return rpc.Empty{}, nil
	case rpc.MPGStatus:
		if !PGInstalled {
			return rpc.PGStatus{Status: "not_installed", Reason: "PostgreSQL client (psql) was not found (mock)"}, nil
		}
		return rpc.PGStatus{Status: "ok", Version: "16.4 (mock)"}, nil
	}
	if !PGInstalled {
		return nil, &rpc.Error{Code: "pg_not_installed", Message: "mock"}
	}
	mockPG.Lock()
	defer mockPG.Unlock()
	switch method {
	case rpc.MPGCreate, rpc.MPGDrop, rpc.MPGPassword:
		var p rpc.PGDB
		conv(params, &p)
		if !ownedBy(p.Owner, p.Name) {
			return nil, &rpc.Error{Code: "db_prefix_required", Message: p.Name}
		}
		switch method {
		case rpc.MPGCreate:
			mockPG.dbs[p.Name] = true
		case rpc.MPGDrop:
			delete(mockPG.dbs, p.Name)
		}
	case rpc.MPGLimit:
	case rpc.MPGSizes:
		var p rpc.PGSizesReq
		conv(params, &p)
		out := rpc.DBSizes{Sizes: map[string]int64{}}
		for n := range mockPG.dbs {
			if ownedBy(p.Owner, n) {
				out.Sizes[n] = 7 << 20
			}
		}
		return out, nil
	}
	return rpc.Empty{}, nil
}
