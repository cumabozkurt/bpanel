//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

// Dev-mode answer for webx.apply: the config is validated exactly like the
// real agent does (so the UI shows real validation errors), nothing is
// written and no web server is touched.

import (
	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
	"github.com/cumabozkurt/bpanel/internal/webx"
)

func mockWebx(params any) (any, error) {
	var p rpc.WebxApplyParams
	if err := conv(params, &p); err != nil {
		return nil, &rpc.Error{Code: "bad_params"}
	}
	if validate.Username(p.User) != nil || p.Vhost.User != p.User {
		return nil, &rpc.Error{Code: "bad_params"}
	}
	c := p.Config
	if err := c.Normalize(); err != nil {
		if e, ok := err.(*webx.Error); ok {
			return nil, &rpc.Error{Code: e.Code, Message: e.Msg}
		}
		return nil, &rpc.Error{Code: "webx_invalid"}
	}
	if c.Domain != p.Vhost.Domain {
		return nil, &rpc.Error{Code: "webx_invalid", Message: "vhost does not match the domain"}
	}
	return rpc.WebxApplyResult{Status: "applied", Wired: !c.Empty()}, nil
}
