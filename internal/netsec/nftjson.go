// SPDX-License-Identifier: Apache-2.0

package netsec

import (
	"encoding/json"
	"fmt"
	"time"
)

// ParseSetJSON parses `nft -j list set inet bpanel <set>` into blocks.
// Elements are a bare string, {"prefix":{"addr","len"}}, or
// {"elem":{"val":<string|prefix>,"timeout":N,"expires":N}}.
func ParseSetJSON(data []byte, now time.Time) ([]Block, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nft json: %w", err)
	}
	var out []Block
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("nft json set: %w", err)
		}
		for _, e := range set.Elem {
			b, err := parseElem(e, now)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
	}
	return out, nil
}

func parseVal(raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil
	}
	var p struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
		Range []string `json:"range"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("nft json elem: %w", err)
	}
	if p.Prefix != nil {
		return fmt.Sprintf("%s/%d", p.Prefix.Addr, p.Prefix.Len), nil
	}
	if len(p.Range) == 2 {
		return p.Range[0] + "-" + p.Range[1], nil
	}
	return "", fmt.Errorf("nft json elem: unknown shape %s", string(raw))
}

func parseElem(raw json.RawMessage, now time.Time) (Block, error) {
	var wrap struct {
		Elem *struct {
			Val     json.RawMessage `json:"val"`
			Timeout int64           `json:"timeout"`
			Expires int64           `json:"expires"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &wrap) == nil && wrap.Elem != nil {
		v, err := parseVal(wrap.Elem.Val)
		if err != nil {
			return Block{}, err
		}
		b := Block{IP: norm(v), Source: "kernel"}
		if wrap.Elem.Expires > 0 {
			b.ExpiresAt = now.Add(time.Duration(wrap.Elem.Expires) * time.Second)
		}
		return b, nil
	}
	v, err := parseVal(raw)
	if err != nil {
		return Block{}, err
	}
	return Block{IP: norm(v), Source: "kernel"}, nil
}
