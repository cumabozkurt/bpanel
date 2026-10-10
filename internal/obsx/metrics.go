// SPDX-License-Identifier: Apache-2.0

// Package obsx is the v0.4 observability core of BPANEL (spec §8, §14, §15):
// a stdlib Prometheus text-exposition writer, the alert dedup/cooldown and
// incident state machine, file-integrity baselines and OS-health parsers.
// It has no dependency on the API or the agent so it can be unit-tested
// directly.
package obsx

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Label is one name="value" pair.
type Label struct{ Name, Value string }

// L builds labels from alternating name, value strings.
func L(kv ...string) []Label {
	out := make([]Label, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, Label{kv[i], kv[i+1]})
	}
	return out
}

func escLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

func escHelp(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	return strings.ReplaceAll(v, "\n", `\n`)
}

func labelStr(ls []Label, extra ...Label) string {
	all := append(append([]Label{}, ls...), extra...)
	if len(all) == 0 {
		return ""
	}
	parts := make([]string, len(all))
	for i, l := range all {
		parts[i] = l.Name + `="` + escLabel(l.Value) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func fmtFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// Sample is one gauge/counter value.
type Sample struct {
	Labels []Label
	Value  float64
}

// Family is a metric family ready to be written.
type Family struct {
	Name, Help, Type string // Type: counter | gauge | histogram
	Samples          []Sample
	Hist             []HistSample
}

// HistSample is one labelled histogram series.
type HistSample struct {
	Labels  []Label
	Buckets []float64 // upper bounds, ascending, without +Inf
	Counts  []uint64  // cumulative counts per bucket
	Count   uint64
	Sum     float64
}

// WriteText writes families in the Prometheus text exposition format 0.0.4.
// Families are sorted by name; samples keep their order.
func WriteText(w io.Writer, fams []Family) error {
	sort.SliceStable(fams, func(i, j int) bool { return fams[i].Name < fams[j].Name })
	for _, f := range fams {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.Name, escHelp(f.Help), f.Name, f.Type); err != nil {
			return err
		}
		for _, s := range f.Samples {
			if _, err := fmt.Fprintf(w, "%s%s %s\n", f.Name, labelStr(s.Labels), fmtFloat(s.Value)); err != nil {
				return err
			}
		}
		for _, h := range f.Hist {
			for i, b := range h.Buckets {
				fmt.Fprintf(w, "%s_bucket%s %d\n", f.Name, labelStr(h.Labels, Label{"le", fmtFloat(b)}), h.Counts[i])
			}
			fmt.Fprintf(w, "%s_bucket%s %d\n", f.Name, labelStr(h.Labels, Label{"le", "+Inf"}), h.Count)
			fmt.Fprintf(w, "%s_sum%s %s\n", f.Name, labelStr(h.Labels), fmtFloat(h.Sum))
			if _, err := fmt.Fprintf(w, "%s_count%s %d\n", f.Name, labelStr(h.Labels), h.Count); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- in-process collectors -------------------------------------------------

// DefaultBuckets are request latency buckets in seconds.
var DefaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histSeries struct {
	counts []uint64
	count  uint64
	sum    float64
}

// Recorder keeps the in-process counters (HTTP requests, agent calls).
// It is safe for concurrent use.
type Recorder struct {
	mu      sync.Mutex
	reqs    map[[3]string]uint64 // method, route, code class
	lat     map[[2]string]*histSeries
	agent   map[[2]string]uint64 // method, result ok|error
	buckets []float64
}

func NewRecorder() *Recorder {
	return &Recorder{reqs: map[[3]string]uint64{}, lat: map[[2]string]*histSeries{}, agent: map[[2]string]uint64{}, buckets: DefaultBuckets}
}

// ObserveHTTP records one request. route should be the chi route pattern
// (bounded cardinality), never the raw path.
func (r *Recorder) ObserveHTTP(method, route string, status int, d time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	code := strconv.Itoa(status/100) + "xx"
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs[[3]string{method, route, code}]++
	k := [2]string{method, route}
	h := r.lat[k]
	if h == nil {
		h = &histSeries{counts: make([]uint64, len(r.buckets))}
		r.lat[k] = h
	}
	sec := d.Seconds()
	for i, b := range r.buckets {
		if sec <= b {
			h.counts[i]++
		}
	}
	h.count++
	h.sum += sec
}

// ObserveAgent records one agent RPC.
func (r *Recorder) ObserveAgent(method string, err error) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	r.mu.Lock()
	r.agent[[2]string{method, res}]++
	r.mu.Unlock()
}

// Families returns the recorder's metric families.
func (r *Recorder) Families() []Family {
	r.mu.Lock()
	defer r.mu.Unlock()
	req := Family{Name: "bpanel_http_requests_total", Help: "HTTP requests by method, route pattern and status class.", Type: "counter"}
	for k, v := range r.reqs {
		req.Samples = append(req.Samples, Sample{L("method", k[0], "route", k[1], "code", k[2]), float64(v)})
	}
	sortSamples(req.Samples)
	lat := Family{Name: "bpanel_http_request_duration_seconds", Help: "HTTP request latency.", Type: "histogram"}
	keys := make([][2]string, 0, len(r.lat))
	for k := range r.lat {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		h := r.lat[k]
		lat.Hist = append(lat.Hist, HistSample{Labels: L("method", k[0], "route", k[1]), Buckets: r.buckets,
			Counts: append([]uint64{}, h.counts...), Count: h.count, Sum: h.sum})
	}
	ag := Family{Name: "bpanel_agent_calls_total", Help: "Root agent RPC calls by method and result.", Type: "counter"}
	for k, v := range r.agent {
		ag.Samples = append(ag.Samples, Sample{L("method", k[0], "result", k[1]), float64(v)})
	}
	sortSamples(ag.Samples)
	return []Family{req, lat, ag}
}

func sortSamples(s []Sample) {
	sort.Slice(s, func(i, j int) bool { return labelStr(s[i].Labels) < labelStr(s[j].Labels) })
}
