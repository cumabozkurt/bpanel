package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// PowerDNS Authoritative is driven through its HTTP API on 127.0.0.1.

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRSet struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        int          `json:"ttl,omitempty"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records"`
}

type pdnsZone struct {
	Name        string      `json:"name"`
	Kind        string      `json:"kind,omitempty"`
	Nameservers []string    `json:"nameservers"`
	SOAEditAPI  string      `json:"soa_edit_api,omitempty"`
	Serial      int64       `json:"serial,omitempty"`
	RRSets      []pdnsRRSet `json:"rrsets"`
}

func fqdn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func (a *Agent) pdns(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.Cfg.PDNSURL, "/")+"/api/v1/servers/localhost"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", a.Cfg.PDNSKey)
	req.Header.Set("Content-Type", "application/json")
	cl := &http.Client{Timeout: 15 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return errf("pdns_unreachable", "%v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return errf("pdns_unreachable", "%v", err)
	}
	if resp.StatusCode >= 300 {
		return errf("pdns_error", "%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

// NormalizeContent converts user-facing record content to PowerDNS presentation format.
func NormalizeContent(t, c string) string {
	c = strings.TrimSpace(c)
	switch t {
	case "CNAME", "NS":
		return fqdn(c)
	case "MX":
		f := strings.Fields(c)
		if len(f) == 2 {
			return f[0] + " " + fqdn(f[1])
		}
	case "SRV":
		f := strings.Fields(c)
		if len(f) == 4 {
			return f[0] + " " + f[1] + " " + f[2] + " " + fqdn(f[3])
		}
	case "TXT":
		if strings.HasPrefix(c, `"`) {
			return c
		}
		c = strings.ReplaceAll(c, `"`, `\"`)
		var parts []string
		for len(c) > 255 {
			parts = append(parts, `"`+c[:255]+`"`)
			c = c[255:]
		}
		parts = append(parts, `"`+c+`"`)
		return strings.Join(parts, " ")
	}
	return c
}

func checkZone(z string) error {
	if err := validate.Domain(strings.TrimSuffix(z, ".")); err != nil {
		return errf("invalid_zone", "%s", z)
	}
	return nil
}

func (a *Agent) dnsZoneCreate(ctx context.Context, p rpc.DNSZone) (_ rpc.Empty, rerr error) {
	if err := checkZone(p.Zone); err != nil {
		return rpc.Empty{}, err
	}
	// CODE-27: a new zone is registered to its account; Replace (reset) on
	// an existing zone requires the same owner.
	if p.Replace {
		if err := a.mustOwn(kindZone, p.Zone, p.Owner); err != nil {
			return rpc.Empty{}, err
		}
	} else {
		_, had, err := a.readOwner(kindZone, p.Zone)
		if err != nil {
			return rpc.Empty{}, err
		}
		if err := a.claim(kindZone, p.Zone, p.Owner, ""); err != nil {
			return rpc.Empty{}, err
		}
		if !had {
			defer func() {
				if rerr != nil {
					_ = a.release(kindZone, p.Zone, p.Owner)
				}
			}()
		}
	}
	zone := strings.TrimSuffix(strings.ToLower(p.Zone), ".")
	groups := map[string]*pdnsRRSet{}
	var nameservers []string
	for _, r := range p.Records {
		if !validate.DNSTypes[r.Type] {
			return rpc.Empty{}, errf("invalid_record_type", "%s", r.Type)
		}
		name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if err := validate.RecordName(zone, name); err != nil {
			return rpc.Empty{}, errf(err.Error(), "%s", r.Name)
		}
		if err := validate.RecordContent(r.Type, r.Content); err != nil {
			return rpc.Empty{}, errf(err.Error(), "%s", r.Content)
		}
		if r.Type == "NS" && name == zone {
			nameservers = append(nameservers, fqdn(r.Content))
			continue
		}
		k := name + "|" + r.Type
		g, ok := groups[k]
		if !ok {
			ttl := r.TTL
			if ttl <= 0 {
				ttl = 3600
			}
			g = &pdnsRRSet{Name: fqdn(name), Type: r.Type, TTL: ttl}
			groups[k] = g
		}
		g.Records = append(g.Records, pdnsRecord{Content: NormalizeContent(r.Type, r.Content)})
	}
	z := pdnsZone{Name: fqdn(zone), Kind: "Native", Nameservers: nameservers, SOAEditAPI: "DEFAULT"}
	for _, g := range groups {
		z.RRSets = append(z.RRSets, *g)
	}
	defer a.lock("dns")()
	var existing pdnsZone
	err := a.pdns(ctx, "GET", "/zones/"+fqdn(zone), nil, &existing)
	switch {
	case err == nil && !p.Replace:
		// Never silently delete and re-create a zone (it may belong to another
		// account, carry custom records, DNSSEC keys or metadata).
		return rpc.Empty{}, errf("zone_exists", "zone %s already exists", zone)
	case err == nil:
		return rpc.Empty{}, a.replaceZone(ctx, zone, existing, z)
	case !isPDNSNotFound(err):
		return rpc.Empty{}, err
	}
	return rpc.Empty{}, a.pdns(ctx, "POST", "/zones", z, nil)
}

func isPDNSNotFound(err error) bool {
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != "pdns_error" {
		return false
	}
	return strings.Contains(re.Message, ": 404") || strings.Contains(re.Message, ": 422 ") && strings.Contains(re.Message, "Could not find")
}

// replaceZone resets an existing zone in place with one PATCH: every record
// set of the template is replaced, every other set (except SOA) is deleted.
func (a *Agent) replaceZone(ctx context.Context, zone string, existing pdnsZone, z pdnsZone) error {
	want := map[string]bool{}
	var patch []pdnsRRSet
	for _, rr := range z.RRSets {
		rr.ChangeType = "REPLACE"
		want[rr.Name+"|"+rr.Type] = true
		patch = append(patch, rr)
	}
	if len(z.Nameservers) > 0 {
		ns := pdnsRRSet{Name: fqdn(zone), Type: "NS", TTL: 86400, ChangeType: "REPLACE"}
		for _, n := range z.Nameservers {
			ns.Records = append(ns.Records, pdnsRecord{Content: n})
		}
		want[ns.Name+"|NS"] = true
		patch = append(patch, ns)
	}
	for _, rr := range existing.RRSets {
		if rr.Type == "SOA" || want[rr.Name+"|"+rr.Type] {
			continue
		}
		patch = append(patch, pdnsRRSet{Name: rr.Name, Type: rr.Type, ChangeType: "DELETE", Records: []pdnsRecord{}})
	}
	return a.pdns(ctx, "PATCH", "/zones/"+fqdn(zone), map[string]any{"rrsets": patch}, nil)
}

func (a *Agent) dnsZoneDelete(ctx context.Context, p rpc.ZoneRef) (rpc.Empty, error) {
	if err := checkZone(p.Zone); err != nil {
		return rpc.Empty{}, err
	}
	if err := a.mustOwn(kindZone, p.Zone, p.Owner); err != nil {
		return rpc.Empty{}, err
	}
	unlock := a.lock("dns")
	err := a.pdns(ctx, "DELETE", "/zones/"+fqdn(p.Zone), nil, nil)
	unlock()
	if err != nil && isPDNSNotFound(err) {
		err = nil
	}
	if err == nil {
		err = a.release(kindZone, p.Zone, p.Owner)
	}
	return rpc.Empty{}, err
}

func (a *Agent) dnsZoneGet(ctx context.Context, p rpc.ZoneRef) (rpc.DNSZone, error) {
	out := rpc.DNSZone{Zone: strings.TrimSuffix(p.Zone, ".")}
	if err := checkZone(p.Zone); err != nil {
		return out, err
	}
	if err := a.mustOwn(kindZone, p.Zone, p.Owner); err != nil {
		return out, err
	}
	var z pdnsZone
	if err := a.pdns(ctx, "GET", "/zones/"+fqdn(p.Zone), nil, &z); err != nil {
		if isPDNSNotFound(err) {
			return out, errf("not_found", "zone %s does not exist", p.Zone)
		}
		return out, err
	}
	out.Serial = z.Serial
	for _, rr := range z.RRSets {
		for _, r := range rr.Records {
			out.Records = append(out.Records, rpc.DNSRecord{Name: strings.TrimSuffix(rr.Name, "."), Type: rr.Type,
				TTL: rr.TTL, Content: r.Content, Disabled: r.Disabled})
		}
	}
	sort.SliceStable(out.Records, func(i, j int) bool {
		if out.Records[i].Name != out.Records[j].Name {
			return len(out.Records[i].Name) < len(out.Records[j].Name) || len(out.Records[i].Name) == len(out.Records[j].Name) && out.Records[i].Name < out.Records[j].Name
		}
		return out.Records[i].Type < out.Records[j].Type
	})
	return out, nil
}

func (a *Agent) dnsRRSetReplace(ctx context.Context, p rpc.RRSet) (rpc.Empty, error) {
	if err := checkZone(p.Zone); err != nil {
		return rpc.Empty{}, err
	}
	if err := a.mustOwn(kindZone, p.Zone, p.Owner); err != nil {
		return rpc.Empty{}, err
	}
	zone := strings.TrimSuffix(strings.ToLower(p.Zone), ".")
	if !validate.DNSTypes[p.Type] {
		return rpc.Empty{}, errf("invalid_record_type", "%s", p.Type)
	}
	if err := validate.RecordName(zone, p.Name); err != nil {
		return rpc.Empty{}, errf(err.Error(), "%s", p.Name)
	}
	if len(p.Records) == 0 {
		return a.dnsRRSetDelete(ctx, rpc.RRSetRef{Owner: p.Owner, Zone: p.Zone, Name: p.Name, Type: p.Type})
	}
	if p.TTL <= 0 {
		p.TTL = 3600
	}
	if p.TTL < 60 || p.TTL > 604800 {
		return rpc.Empty{}, errf("invalid_ttl", "%d", p.TTL)
	}
	if len(p.Records) > 100 {
		return rpc.Empty{}, errf("invalid_record_content", "too many records")
	}
	rr := pdnsRRSet{Name: fqdn(p.Name), Type: p.Type, TTL: p.TTL, ChangeType: "REPLACE"}
	for _, c := range p.Records {
		if err := validate.RecordContent(p.Type, c); err != nil {
			return rpc.Empty{}, errf(err.Error(), "%s", c)
		}
		rr.Records = append(rr.Records, pdnsRecord{Content: NormalizeContent(p.Type, c)})
	}
	defer a.lock("dns")()
	return rpc.Empty{}, a.pdns(ctx, "PATCH", "/zones/"+fqdn(zone), map[string]any{"rrsets": []pdnsRRSet{rr}}, nil)
}

func (a *Agent) dnsRRSetDelete(ctx context.Context, p rpc.RRSetRef) (rpc.Empty, error) {
	if err := checkZone(p.Zone); err != nil {
		return rpc.Empty{}, err
	}
	if err := a.mustOwn(kindZone, p.Zone, p.Owner); err != nil {
		return rpc.Empty{}, err
	}
	zone := strings.TrimSuffix(strings.ToLower(p.Zone), ".")
	if err := validate.RecordName(zone, p.Name); err != nil {
		return rpc.Empty{}, errf(err.Error(), "%s", p.Name)
	}
	if !validate.DNSTypes[p.Type] {
		return rpc.Empty{}, errf("invalid_record_type", "%s", p.Type)
	}
	if p.Type == "SOA" || (p.Type == "NS" && strings.TrimSuffix(strings.ToLower(p.Name), ".") == zone) {
		return rpc.Empty{}, errf("refused", "the zone apex SOA/NS records cannot be deleted")
	}
	rr := pdnsRRSet{Name: fqdn(p.Name), Type: p.Type, ChangeType: "DELETE", Records: []pdnsRecord{}}
	defer a.lock("dns")()
	return rpc.Empty{}, a.pdns(ctx, "PATCH", "/zones/"+fqdn(zone), map[string]any{"rrsets": []pdnsRRSet{rr}}, nil)
}
