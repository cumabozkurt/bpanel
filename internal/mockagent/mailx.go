//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"errors"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/mailx"
)

// mockMailx validates like the real agent but never pretends Sieve, Rspamd
// or a mail log exist: it reports not_installed (dev mock agent).
func mockMailx(method string, params any) (any, error) {
	const why = "dev mock agent: no Dovecot Pigeonhole / Rspamd / Postfix log"
	verr := func(err error) error {
		var me *mailx.Error
		if errors.As(err, &me) {
			return &rpc.Error{Code: me.Code, Message: me.Field}
		}
		return err
	}
	switch method {
	case rpc.MMailSieveApply:
		var p rpc.MailSieveReq
		conv(params, &p)
		s, err := mailx.Generate(p.Email, p.Vacation, p.Rules)
		if err != nil {
			return nil, verr(err)
		}
		if s == "" {
			return rpc.MailxStatus{Status: "inactive"}, nil
		}
		return rpc.MailxStatus{Status: "not_installed", Reason: why}, nil
	case rpc.MMailSpamApply:
		var p rpc.MailSpamReq
		conv(params, &p)
		if _, err := mailx.RenderRspamd(p.User, p.Domains, p.Policy); err != nil {
			return nil, verr(err)
		}
		return rpc.MailxStatus{Status: "not_installed", Reason: why}, nil
	case rpc.MMailLogSearch:
		return rpc.MailLogResult{Status: "not_installed", Reason: why, Entries: []mailx.Delivery{}}, nil
	}
	return nil, &rpc.Error{Code: "unknown_method", Message: method}
}
