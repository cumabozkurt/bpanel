// SPDX-License-Identifier: Apache-2.0

// Package cloudflare is an optional, free-tier-only Cloudflare integration:
// verify an API token, list zones and DNS records, and create records that
// exist in the panel's zone but not on Cloudflare. It never requires a paid
// product and is not needed by any other feature (detect-only when no
// token is stored: see Detect).
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBase is the public API; tests and air-gapped setups override it.
const DefaultBase = "https://api.cloudflare.com/client/v4"

type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

type Zone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	NameServers []string `json:"name_servers"`
	Plan        struct {
		Name string `json:"name"`
	} `json:"plan"`
}

type Record struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Proxied  bool   `json:"proxied,omitempty"`
	Priority *int   `json:"priority,omitempty"`
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int
		Message string
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	base := c.Base
	if base == "" {
		base = DefaultBase
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return &Error{Code: "cloudflare_unreachable", Msg: "cannot reach the Cloudflare API"}
	}
	defer resp.Body.Close()
	var env envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&env); err != nil {
		return &Error{Code: "cloudflare_bad_response", Msg: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if !env.Success {
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if len(env.Errors) > 0 {
			msg = env.Errors[0].Message
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return &Error{Code: "cloudflare_auth", Msg: msg}
		}
		return &Error{Code: "cloudflare_error", Msg: msg}
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Verify checks the token (GET /user/tokens/verify).
func (c *Client) Verify(ctx context.Context) error {
	var r struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, "GET", "/user/tokens/verify", nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return &Error{Code: "cloudflare_auth", Msg: "token is " + r.Status}
	}
	return nil
}

func (c *Client) Zones(ctx context.Context, name string) ([]Zone, error) {
	q := url.Values{"per_page": {"50"}}
	if name != "" {
		q.Set("name", name)
	}
	var z []Zone
	err := c.do(ctx, "GET", "/zones?"+q.Encode(), nil, &z)
	return z, err
}

func (c *Client) Records(ctx context.Context, zoneID string) ([]Record, error) {
	var r []Record
	err := c.do(ctx, "GET", "/zones/"+url.PathEscape(zoneID)+"/dns_records?per_page=500", nil, &r)
	return r, err
}

func (c *Client) Create(ctx context.Context, zoneID string, rec Record) error {
	return c.do(ctx, "POST", "/zones/"+url.PathEscape(zoneID)+"/dns_records", rec, nil)
}

// Missing returns the records of want (panel zone) that Cloudflare lacks
// (same type, name and content). Only A, AAAA, CNAME, MX and TXT are synced;
// NS/SOA stay with Cloudflare.
func Missing(have, want []Record) []Record {
	key := func(r Record) string {
		return strings.ToUpper(r.Type) + " " + strings.ToLower(strings.TrimSuffix(r.Name, ".")) + " " + strings.TrimSuffix(strings.Trim(r.Content, `"`), ".")
	}
	seen := map[string]bool{}
	for _, r := range have {
		seen[key(r)] = true
	}
	out := []Record{}
	for _, r := range want {
		switch strings.ToUpper(r.Type) {
		case "A", "AAAA", "CNAME", "MX", "TXT":
		default:
			continue
		}
		if !seen[key(r)] {
			seen[key(r)] = true
			out = append(out, r)
		}
	}
	return out
}

// Detect reports whether a domain's nameservers are Cloudflare's (no token
// needed: a plain NS lookup).
func Detect(ctx context.Context, domain string, lookupNS func(context.Context, string) ([]*net.NS, error)) (bool, []string) {
	ns, err := lookupNS(ctx, domain)
	if err != nil {
		return false, []string{}
	}
	out := []string{}
	cf := false
	for _, n := range ns {
		h := strings.ToLower(strings.TrimSuffix(n.Host, "."))
		out = append(out, h)
		if strings.HasSuffix(h, ".ns.cloudflare.com") {
			cf = true
		}
	}
	return cf, out
}
