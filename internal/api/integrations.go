// SPDX-License-Identifier: Apache-2.0

package api

// Integration inventory (v0.4, master spec §19): GET /admin/integrations
// lists every registered provider with its license class, capabilities and
// detected state. Admin only. Detection goes through the agent's read-only
// providers.detect; results are cached for 30 s (?refresh=1 bypasses).

import (
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cumabozkurt/bpanel/internal/providers"
)

const integrationsTTL = 30 * time.Second

type integrationsCache struct {
	mu      sync.Mutex
	at      time.Time
	reports []providers.Report
}

var (
	intCacheMu sync.Mutex
	intCaches  = map[*Server]*integrationsCache{}
)

func (s *Server) integrationsCache() *integrationsCache {
	intCacheMu.Lock()
	defer intCacheMu.Unlock()
	c := intCaches[s]
	if c == nil {
		c = &integrationsCache{}
		intCaches[s] = c
	}
	return c
}

// IntegrationsResp is the GET /admin/integrations body.
type IntegrationsResp struct {
	CheckedAt time.Time          `json:"checked_at"`
	Cached    bool               `json:"cached"`
	Providers []providers.Report `json:"providers"`
}

func (s *Server) mountProviders(r chi.Router) {
	s.op(r, "GET", "/admin/integrations", "server", "Integration inventory: providers, license class and detected state (?refresh=1)", nil, s.h(s.listIntegrations))
}

func (s *Server) listIntegrations(w http.ResponseWriter, r *http.Request) (any, error) {
	c := s.integrationsCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	fresh := r.URL.Query().Get("refresh") == "1"
	if !fresh && c.reports != nil && time.Since(c.at) < integrationsTTL {
		return IntegrationsResp{CheckedAt: c.at, Cached: true, Providers: c.reports}, nil
	}
	env := providers.NewEnv(s.Agent, s.features())
	c.reports = providers.Default.DetectAll(r.Context(), env, 20*time.Second)
	c.at = time.Now().UTC()
	return IntegrationsResp{CheckedAt: c.at, Providers: c.reports}, nil
}
