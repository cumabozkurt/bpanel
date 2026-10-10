package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cumabozkurt/bpanel/internal/validate"
)

// ---- G1: limit semantics -----------------------------------------------------
//
// Every limit in the API (package limits, mailbox and FTP quotas, the
// reseller account count and disk pool) follows one rule:
//
//	null or -1  unlimited
//	0           none (count limits only: 0 FTP accounts = FTP is not allowed)
//	n > 0       at most n
//
// Size limits (MB, CPU percent, memory, tasks) cannot be 0: a zero-size
// mailbox or a 0 MB disk is never what an administrator means, so the API
// rejects it (400 invalid_limit, field = the JSON key) instead of guessing.
// Responses always carry -1 for unlimited, never null. Before v0.2-r2, 0
// meant unlimited; migration 0004 turned every stored 0 into -1.

// Unlimited is the stored and returned value for "no limit".
const Unlimited int64 = -1

// Limit is a limit field in a request. It tells "absent" (Set=false) from
// null or -1 (unlimited) and from a number.
type Limit struct {
	Set   bool
	Value int64 // -1 = unlimited
}

// LimitOf returns a set limit (Go callers: seed data, tests).
func LimitOf(v int64) Limit { return Limit{Set: true, Value: v} }

func (l *Limit) UnmarshalJSON(b []byte) error {
	l.Set = true
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		l.Value = Unlimited
		return nil
	}
	var n json.Number
	if len(b) == 0 || b[0] == '"' {
		return fmt.Errorf("limit must be an integer, -1 or null")
	}
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("limit must be an integer, -1 or null")
	}
	v, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return fmt.Errorf("limit must be an integer, -1 or null")
	}
	l.Value = v
	return nil
}

func (l Limit) MarshalJSON() ([]byte, error) {
	if !l.Set {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(l.Value, 10)), nil
}

// or returns the value, or def when the field was absent.
func (l Limit) or(def int64) int64 {
	if !l.Set {
		return def
	}
	return l.Value
}

// Upper bounds (UX-40: 9999999999999999 MB used to be accepted).
const (
	maxCountLimit = 1_000_000
	maxSizeMB     = 1 << 30 // 1 EiB in MB: anything above is a typo
	maxCPUPercent = 100_000
	maxTasksLimit = 10_000_000
)

// checkCount validates a count limit (-1, 0 or 1..maxCountLimit).
func checkCount(field string, v int64) error {
	if v < -1 || v > maxCountLimit {
		return limitErr(field, maxCountLimit, true)
	}
	return nil
}

// checkSize validates a size limit (-1 or 1..max).
func checkSize(field string, v, max int64) error {
	if v == 0 || v < -1 || v > max {
		return limitErr(field, max, false)
	}
	return nil
}

func limitErr(field string, max int64, zeroOK bool) error {
	msg := "use -1 (or null) for unlimited"
	if zeroOK {
		msg += ", 0 for none"
	} else {
		msg += "; 0 is not allowed for sizes"
	}
	return &apiError{Status: 400, Code: "invalid_limit", Field: field, Max: max, Message: msg}
}

// limited reports whether a stored limit restricts anything (-1 = no).
func limited(v int64) bool { return v >= 0 }

// agentLimit converts a stored limit for the agent, whose contract is
// unchanged: 0 = no limit there.
func agentLimit(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// bytesLimit converts an MB limit to bytes for display (-1 stays -1).
func bytesLimit(mb int64) int64 {
	if mb < 0 {
		return Unlimited
	}
	return mb * 1024 * 1024
}

// ---- over-length values (R2-UX-10) -----------------------------------------------

// tooLong is the error for a value longer than its field allows. The API
// never truncates: the client gets the field and the limit (bytes of UTF-8,
// which equals characters for the ASCII-only identifiers).
func tooLong(field string, max int) error {
	return &apiError{Status: 400, Code: "too_long", Field: field, Max: int64(max)}
}

// maxLen returns tooLong when s is longer than max bytes.
func maxLen(field, s string, max int) error {
	if len(s) > max {
		return tooLong(field, max)
	}
	return nil
}

// badField is bad(code) for a named field.
func badField(code, field string) error { return &apiError{Status: 400, Code: code, Field: field} }

// fieldErr turns a validate error into an API error for field (too_long
// gets max).
func fieldErr(err error, field string, max int) error {
	if err.Error() == "too_long" {
		return tooLong(field, max)
	}
	return badField(err.Error(), field)
}

// passwordErr validates a new password and tags the error with its field.
// Over-long passwords keep their code (password_too_long) and carry max.
func passwordErr(pw, field string) error {
	if err := validate.Password(pw); err != nil {
		e := &apiError{Status: 400, Code: err.Error(), Field: field}
		if e.Code == "password_too_long" {
			e.Max = 256
		}
		return e
	}
	return nil
}
