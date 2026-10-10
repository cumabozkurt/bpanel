// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
)

// Install-profile feature gates (R2-SYS-16 handoff, docs/capabilities.md).
// The installer stores feature_<name> = "0"/"1" in the settings table; a
// missing key means "installed" (databases older than v0.2.1). Endpoints of
// a feature the profile did not install answer 409 feature_disabled (field
// = the feature) instead of failing in the agent with a 502, and /auth/me
// reports the flags so the UI hides those tools.

// gatedFeatures are the flags /auth/me reports.
var gatedFeatures = []string{"apache", "dns", "ftp", "mail", "webmail"}

func (s *Server) featureOn(name string) bool { return s.Store.Get("feature_"+name, "1") != "0" }

func (s *Server) features() map[string]bool {
	out := make(map[string]bool, len(gatedFeatures))
	for _, f := range gatedFeatures {
		out[f] = s.featureOn(f)
	}
	// webmail needs mail
	out["webmail"] = out["webmail"] && out["mail"]
	for _, f := range toolFeatures { // v1.1 optional tools (Tweak Settings)
		out[f] = s.featureOn(f)
	}
	out["email_routing"] = out["email_routing"] && out["mail"]
	out["boxtrapper"] = out["boxtrapper"] && out["mail"]
	out["calendars"] = out["calendars"] && out["mail"]
	return out
}

// featureOf maps a route to the feature it needs ("" = always available).
// GET /user/ftp stays open: it also carries the SFTP connection details,
// which every profile provides.
func featureOf(method, path string) []string {
	switch {
	case strings.HasPrefix(path, "/user/dns/"):
		return []string{"dns"}
	case strings.HasPrefix(path, "/user/email/routing"):
		return []string{"mail", "email_routing"}
	case strings.HasPrefix(path, "/user/email/boxtrapper"):
		return []string{"mail", "boxtrapper"}
	case strings.HasPrefix(path, "/user/email/"):
		return []string{"mail"}
	case strings.HasPrefix(path, "/user/calendars"):
		return []string{"mail", "calendars"}
	case strings.HasPrefix(path, "/user/stats/visitors"):
		return []string{"visitors"}
	case strings.HasPrefix(path, "/user/gpg"):
		return []string{"encryption"}
	case strings.HasPrefix(path, "/user/ssh-keys"):
		return []string{"ssh_keys"}
	case strings.HasPrefix(path, "/user/site-publisher"):
		return []string{"site_publisher"}
	case strings.HasPrefix(path, "/user/images"):
		return []string{"images"}
	case strings.HasPrefix(path, "/user/postgresql/browser"):
		return []string{"pg_browser"}
	case strings.HasPrefix(path, "/user/cloudflare"):
		return []string{"cloudflare"}
	case strings.HasPrefix(path, "/user/web/") && strings.Contains(path, "/leech"):
		return []string{"leech_protection"}
	case path == "/user/webmail":
		return []string{"mail", "webmail"}
	case strings.HasPrefix(path, "/user/ftp") && method != http.MethodGet:
		return []string{"ftp"}
	}
	return nil
}

func (s *Server) featureGate(method, path string, h http.HandlerFunc) http.HandlerFunc {
	need := featureOf(method, path)
	if len(need) == 0 {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, f := range need {
			if !s.featureOn(f) {
				writeJSON(w, http.StatusConflict, apiError{Code: "feature_disabled", Field: f,
					Message: f + " is not installed on this server (install profile)"})
				return
			}
		}
		h(w, r)
	}
}
