// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 clusterx: DNS cluster (PowerDNS native primary/secondary: AXFR +
// NOTIFY, optionally pushing slave zones to remote PowerDNS servers through
// their own free HTTP API) and the signed, declarative plugin system.
// Admin-only (server-level). The privileged parts (pdns config, writing
// plugin files) go through the agent; signatures, manifests and SOA queries
// are checked here with internal/clusterx.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/clusterx"
	"github.com/cumabozkurt/bpanel/internal/rbac"
)

// PluginRoot is where the agent installs plugins (read-only for the API).
var PluginRoot = "/usr/local/bpanel/plugins"

// clusterSOATimeout bounds one SOA query; clusterMaxZones bounds a status run.
var (
	clusterSOATimeout = 3 * time.Second
	clusterMaxZones   = 500
	clusterQuerySOA   = clusterx.QuerySOA
)

type ClusterSecondaryReq struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

type ClusterRemoteReq struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	APIKey    string `json:"api_key"`
	PrimaryIP string `json:"primary_ip"`
}

type PluginArchiveReq struct {
	Archive string `json:"archive"` // base64 .tar.gz
}

type PluginEnableReq struct {
	Enabled bool `json:"enabled"`
}

type PluginKeyReq struct {
	Name   string `json:"name"`
	PubKey string `json:"pubkey"`
}

func (s *Server) mountClusterx(r chi.Router) {
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/dns-cluster", "dns", "DNS cluster: secondary nameservers, remote PowerDNS APIs, last apply result", nil, s.h(s.clusterGet))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/dns-cluster/secondaries", "dns", "Add a secondary nameserver IP (AXFR allowed + NOTIFY) and apply", ClusterSecondaryReq{}, s.h(s.clusterAddSecondary))
	s.opPerm(r, rbac.ServerWrite, "DELETE", "/admin/dns-cluster/secondaries/{id}", "dns", "Remove a secondary nameserver and apply", nil, s.h(s.clusterDelSecondary))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/dns-cluster/apply", "dns", "Re-apply the PowerDNS cluster configuration and notify every zone", nil, s.h(s.clusterApplyH))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/dns-cluster/status", "dns", "SOA serial of every zone on the primary and each secondary (in_sync / behind / unreachable)", nil, s.h(s.clusterStatus))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/dns-cluster/remotes", "dns", "Add a remote PowerDNS server driven through its HTTP API (key kept in the secret store)", ClusterRemoteReq{}, s.h(s.clusterAddRemote))
	s.opPerm(r, rbac.ServerWrite, "DELETE", "/admin/dns-cluster/remotes/{id}", "dns", "Remove a remote PowerDNS server", nil, s.h(s.clusterDelRemote))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/dns-cluster/remotes/{id}/sync", "dns", "Create every local zone as a slave zone on the remote PowerDNS (existing zones are kept)", nil, s.h(s.clusterSyncRemote))

	s.opPerm(r, rbac.ServerRead, "GET", "/admin/plugins", "plugins", "Installed plugins, trusted signing keys and the permission allowlist", nil, s.h(s.pluginList))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/plugins/inspect", "plugins", "Check a plugin archive (safe extraction, manifest, signature) and show its capabilities without installing", PluginArchiveReq{}, s.h(s.pluginInspect))
	s.opPermReauth(r, rbac.ServerWrite, "POST", "/admin/plugins", "plugins", "Install a signed plugin archive (installed disabled)", PluginArchiveReq{}, s.h(s.pluginInstall))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/plugins/{name}/enable", "plugins", "Enable or disable a plugin (enabling registers its webhook hooks)", PluginEnableReq{}, s.h(s.pluginEnable))
	s.opPerm(r, rbac.ServerWrite, "DELETE", "/admin/plugins/{name}", "plugins", "Remove a plugin (files and hooks)", nil, s.h(s.pluginRemove))
	s.opPermReauth(r, rbac.ServerWrite, "POST", "/admin/plugin-keys", "plugins", "Trust an ed25519 plugin signing key", PluginKeyReq{}, s.h(s.pluginKeyAdd))
	s.opPerm(r, rbac.ServerWrite, "DELETE", "/admin/plugin-keys/{id}", "plugins", "Stop trusting a plugin signing key", nil, s.h(s.pluginKeyDel))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/plugins/{name}/ui/*", "plugins", "Static UI files of an enabled plugin (sandboxed: opaque origin, no panel session)", nil, s.pluginAsset)
}

func clusterAPIErr(err error) error {
	var e *clusterx.Error
	if errors.As(err, &e) {
		return badMsg(e.Code, e.Msg)
	}
	return err
}

func clusterAdminOnly(r *http.Request) error {
	if u := userOf(r); u == nil || u.Role != "admin" {
		return &apiError{Status: 403, Code: "forbidden"}
	}
	return nil
}

// ---- DNS cluster ------------------------------------------------------------------

type clusterSecondary struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
}

type clusterRemote struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	PrimaryIP string `json:"primary_ip"`
	LastSync  int64  `json:"last_sync"`
	LastError string `json:"last_error"`
}

func (s *Server) clusterSecondaries(ctx context.Context) ([]clusterSecondary, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, ip, name, created_at FROM dns_cluster_secondaries ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []clusterSecondary{}
	for rows.Next() {
		var x clusterSecondary
		if err := rows.Scan(&x.ID, &x.IP, &x.Name, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Server) clusterZones(ctx context.Context) ([]string, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT name FROM domains WHERE kind IN ('main','addon','alias') ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Server) clusterGet(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	sec, err := s.clusterSecondaries(r.Context())
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id, name, url, primary_ip, last_sync, last_error FROM dns_cluster_remotes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rem := []clusterRemote{}
	for rows.Next() {
		var x clusterRemote
		if err := rows.Scan(&x.ID, &x.Name, &x.URL, &x.PrimaryIP, &x.LastSync, &x.LastError); err != nil {
			return nil, err
		}
		rem = append(rem, x)
	}
	var last any
	if v := s.Store.Get("clusterx_last_apply", ""); v != "" {
		_ = json.Unmarshal([]byte(v), &last)
	}
	return map[string]any{"secondaries": sec, "remotes": rem, "last_apply": last,
		"primary_query": s.Store.Get("clusterx_primary_addr", "127.0.0.1:53")}, nil
}

// clusterApply pushes the current secondary list to the agent.
func (s *Server) clusterApply(r *http.Request) (rpc.ClusterApplyResult, error) {
	var out rpc.ClusterApplyResult
	sec, err := s.clusterSecondaries(r.Context())
	if err != nil {
		return out, err
	}
	zones, err := s.clusterZones(r.Context())
	if err != nil {
		return out, err
	}
	ips := make([]string, 0, len(sec))
	for _, x := range sec {
		ips = append(ips, x.IP)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Minute)
	defer cancel()
	if err := s.agentCall(r.WithContext(ctx), rpc.MClusterApply, rpc.ClusterApplyReq{Secondaries: ips, Zones: zones}, &out); err != nil {
		s.audit(r, "dns.cluster.apply", strings.Join(ips, ","), nsAgentCode(err), false)
		return out, err
	}
	b, _ := json.Marshal(map[string]any{"at": s.Now().Unix(), "status": out.Status, "reason": out.Reason,
		"notified": out.Notified, "zone_errors": len(out.ZoneErrors)})
	_ = s.Store.Set("clusterx_last_apply", string(b))
	s.audit(r, "dns.cluster.apply", strings.Join(ips, ","), out.Status, true)
	return out, nil
}

func (s *Server) clusterAddSecondary(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	var in ClusterSecondaryReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ip, err := clusterx.ValidateSecondaryIP(in.IP)
	if err != nil {
		return nil, clusterAPIErr(err)
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) > 64 {
		return nil, bad("invalid_name")
	}
	var n int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM dns_cluster_secondaries`).Scan(&n)
	if n >= clusterx.MaxSecondaries {
		return nil, badMsg("cluster_invalid_ip", "too many secondaries")
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO dns_cluster_secondaries(ip,name,created_at) VALUES(?,?,?) ON CONFLICT(ip) DO NOTHING`, ip, in.Name, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return nil, conflict("cluster_duplicate")
	}
	id, _ := res.LastInsertId()
	out, err := s.clusterApply(r)
	if err != nil {
		s.Store.DB.ExecContext(r.Context(), `DELETE FROM dns_cluster_secondaries WHERE id=?`, id)
		return nil, err
	}
	s.audit(r, "dns.cluster.secondary.add", ip, "", true)
	return map[string]any{"id": id, "ip": ip, "apply": out}, nil
}

func (s *Server) clusterDelSecondary(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	var x clusterSecondary
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT id, ip, name, created_at FROM dns_cluster_secondaries WHERE id=?`, idParam(r, "id")).
		Scan(&x.ID, &x.IP, &x.Name, &x.CreatedAt); err != nil {
		return nil, notFound()
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM dns_cluster_secondaries WHERE id=?`, x.ID); err != nil {
		return nil, err
	}
	out, err := s.clusterApply(r)
	if err != nil {
		s.Store.DB.ExecContext(r.Context(), `INSERT OR IGNORE INTO dns_cluster_secondaries(id,ip,name,created_at) VALUES(?,?,?,?)`, x.ID, x.IP, x.Name, x.CreatedAt)
		return nil, err
	}
	s.audit(r, "dns.cluster.secondary.remove", x.IP, "", true)
	return map[string]any{"apply": out}, nil
}

func (s *Server) clusterApplyH(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	return s.clusterApply(r)
}

type clusterZoneState struct {
	Zone          string            `json:"zone"`
	PrimarySerial uint32            `json:"primary_serial"`
	Secondaries   map[string]string `json:"secondaries"` // ip -> state
	Serials       map[string]uint32 `json:"serials"`
}

func (s *Server) clusterStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	sec, err := s.clusterSecondaries(r.Context())
	if err != nil {
		return nil, err
	}
	zones, err := s.clusterZones(r.Context())
	if err != nil {
		return nil, err
	}
	truncated := false
	if len(zones) > clusterMaxZones {
		zones, truncated = zones[:clusterMaxZones], true
	}
	primary := s.Store.Get("clusterx_primary_addr", "127.0.0.1:53")
	out := make([]clusterZoneState, len(zones))
	summary := map[string]map[string]int{}
	for _, x := range sec {
		summary[x.IP] = map[string]int{}
	}
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, z := range zones {
		wg.Add(1)
		go func(i int, z string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p := clusterQuerySOA(r.Context(), primary, z, clusterSOATimeout)
			st := clusterZoneState{Zone: z, PrimarySerial: p.Serial, Secondaries: map[string]string{}, Serials: map[string]uint32{}}
			for _, x := range sec {
				q := clusterQuerySOA(r.Context(), x.IP, z, clusterSOATimeout)
				state := clusterx.CompareSOA(p, q)
				st.Secondaries[x.IP] = state
				if q.Found {
					st.Serials[x.IP] = q.Serial
				}
				mu.Lock()
				summary[x.IP][state]++
				mu.Unlock()
			}
			out[i] = st
		}(i, z)
	}
	wg.Wait()
	return map[string]any{"primary": primary, "zones": out, "summary": summary, "truncated": truncated}, nil
}

func remoteSecret(id int64) string { return "clusterx.remote." + strconv.FormatInt(id, 10) }

func (s *Server) clusterAddRemote(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	var in ClusterRemoteReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Name, in.URL = strings.TrimSpace(in.Name), strings.TrimRight(strings.TrimSpace(in.URL), "/")
	if in.Name == "" || len(in.Name) > 64 {
		return nil, bad("invalid_name")
	}
	if len(in.APIKey) < 8 || len(in.APIKey) > 512 {
		return nil, badMsg("cluster_remote_failed", "api key missing")
	}
	pip, err := clusterx.ValidateSecondaryIP(in.PrimaryIP)
	if err != nil {
		return nil, clusterAPIErr(err)
	}
	if err := s.checkWebhookURL(r.Context(), in.URL); err != nil {
		return nil, err
	}
	if st := s.Secrets(); st.Status()["status"] != "ok" {
		return nil, errSecretsUnavailable
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO dns_cluster_remotes(name,url,primary_ip,created_at) VALUES(?,?,?,?)`, in.Name, in.URL, pip, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := s.Secrets().Put(r.Context(), remoteSecret(id), []byte(in.APIKey)); err != nil {
		s.Store.DB.ExecContext(r.Context(), `DELETE FROM dns_cluster_remotes WHERE id=?`, id)
		return nil, err
	}
	s.audit(r, "dns.cluster.remote.add", in.Name, "", true)
	return map[string]any{"id": id}, nil
}

func (s *Server) clusterDelRemote(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	id := idParam(r, "id")
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM dns_cluster_remotes WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	_ = s.Secrets().Delete(r.Context(), remoteSecret(id))
	s.audit(r, "dns.cluster.remote.remove", strconv.FormatInt(id, 10), "", true)
	return nil, nil
}

func (s *Server) clusterSyncRemote(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	var x clusterRemote
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT id, name, url, primary_ip FROM dns_cluster_remotes WHERE id=?`, idParam(r, "id")).
		Scan(&x.ID, &x.Name, &x.URL, &x.PrimaryIP); err != nil {
		return nil, notFound()
	}
	if err := s.checkWebhookURL(r.Context(), x.URL); err != nil { // re-check: DNS may have changed
		return nil, err
	}
	key, err := s.Secrets().Get(r.Context(), remoteSecret(x.ID))
	if err != nil {
		return nil, errSecretsUnavailable
	}
	zones, err := s.clusterZones(r.Context())
	if err != nil {
		return nil, err
	}
	cl := s.webhookClient() // SSRF guard: re-checks the dialled IP, no redirects
	created, existing, failed := 0, 0, map[string]string{}
	for _, z := range zones {
		body, _ := json.Marshal(map[string]any{"name": strings.TrimSuffix(z, ".") + ".", "kind": "Slave", "masters": []string{x.PrimaryIP}})
		req, err := http.NewRequestWithContext(r.Context(), "POST", x.URL+"/api/v1/servers/localhost/zones", bytes.NewReader(body))
		if err != nil {
			failed[z] = "request"
			continue
		}
		req.Header.Set("X-API-Key", string(key))
		req.Header.Set("Content-Type", "application/json")
		resp, err := cl.Do(req)
		if err != nil {
			failed[z] = "unreachable"
			if errors.Is(err, errBlockedTarget) {
				failed[z] = "blocked"
			}
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 201 || resp.StatusCode == 200 || resp.StatusCode == 204:
			created++
		case resp.StatusCode == 409:
			existing++
		default:
			failed[z] = "http_" + strconv.Itoa(resp.StatusCode)
		}
	}
	lastErr := ""
	if len(failed) > 0 {
		lastErr = fmt.Sprintf("%d zone(s) failed", len(failed))
	}
	s.Store.DB.ExecContext(r.Context(), `UPDATE dns_cluster_remotes SET last_sync=?, last_error=? WHERE id=?`, s.Now().Unix(), lastErr, x.ID)
	s.audit(r, "dns.cluster.remote.sync", x.Name, lastErr, len(failed) == 0)
	if len(failed) > 0 && created+existing == 0 {
		return nil, badMsg("cluster_remote_failed", lastErr)
	}
	return map[string]any{"created": created, "existing": existing, "failed": failed}, nil
}

// ---- plugins ----------------------------------------------------------------------

type pluginRow struct {
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	Author     string             `json:"author"`
	License    string             `json:"license"`
	Signer     string             `json:"signer"`
	Enabled    bool               `json:"enabled"`
	Manifest   *clusterx.Manifest `json:"manifest"`
	WebhookIDs []int64            `json:"webhook_ids"`
	UIURL      string             `json:"ui_url,omitempty"`
}

func scanPlugin(sc interface{ Scan(...any) error }) (pluginRow, error) {
	var x pluginRow
	var mj, wj string
	if err := sc.Scan(&x.Name, &x.Version, &x.Author, &x.License, &mj, &x.Signer, &x.Enabled, &wj); err != nil {
		return x, err
	}
	x.Manifest = &clusterx.Manifest{}
	_ = json.Unmarshal([]byte(mj), x.Manifest)
	_ = json.Unmarshal([]byte(wj), &x.WebhookIDs)
	if x.Enabled && x.Manifest.UIEntry != "" {
		x.UIURL = "/api/v1/admin/plugins/" + x.Name + "/ui/" + x.Manifest.UIEntry
	}
	return x, nil
}

const pluginCols = `name, version, author, license, manifest_json, signer, enabled, webhook_ids`

func (s *Server) pluginByName(ctx context.Context, name string) (pluginRow, error) {
	if !clusterx.ValidName(name) {
		return pluginRow{}, notFound()
	}
	x, err := scanPlugin(s.Store.DB.QueryRowContext(ctx, `SELECT `+pluginCols+` FROM plugins WHERE name=?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return x, notFound()
	}
	return x, err
}

type pluginKey struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	PubKey string `json:"pubkey"`
	KeyID  string `json:"key_id"`
}

func (s *Server) pluginKeys(ctx context.Context) ([]pluginKey, []ed25519.PublicKey, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, name, pubkey, key_id FROM plugin_keys ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out, keys := []pluginKey{}, []ed25519.PublicKey{}
	for rows.Next() {
		var k pluginKey
		if err := rows.Scan(&k.ID, &k.Name, &k.PubKey, &k.KeyID); err != nil {
			return nil, nil, err
		}
		if pk, err := clusterx.ParsePublicKey(k.PubKey); err == nil {
			keys = append(keys, pk)
		}
		out = append(out, k)
	}
	return out, keys, rows.Err()
}

func (s *Server) pluginList(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT `+pluginCols+` FROM plugins ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []pluginRow{}
	for rows.Next() {
		x, err := scanPlugin(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, x)
	}
	keys, _, err := s.pluginKeys(r.Context())
	if err != nil {
		return nil, err
	}
	acts := []string{}
	for a := range clusterx.AgentActions {
		acts = append(acts, a)
	}
	return map[string]any{"plugins": list, "keys": keys, "permissions": clusterx.Permissions, "agent_actions": acts,
		"max_archive_bytes": clusterx.MaxArchiveBytes}, nil
}

// pluginLoad decodes the upload and runs extraction, manifest and signature checks.
func (s *Server) pluginLoad(r *http.Request) ([]byte, map[string][]byte, *clusterx.Manifest, string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, int64(clusterx.MaxArchiveBytes)*4/3+4096)
	var in PluginArchiveReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, nil, nil, "", badMsg("plugin_too_large", "archive too large")
		}
		return nil, nil, nil, "", badMsg("bad_json", err.Error())
	}
	archive, err := base64.StdEncoding.DecodeString(in.Archive)
	if err != nil {
		return nil, nil, nil, "", badMsg("plugin_invalid_archive", "archive must be base64")
	}
	files, m, err := clusterx.Load(archive)
	if err != nil {
		return nil, nil, nil, "", clusterAPIErr(err)
	}
	_, keys, err := s.pluginKeys(r.Context())
	if err != nil {
		return nil, nil, nil, "", err
	}
	signer, err := clusterx.Verify(files, keys)
	if err != nil {
		return nil, nil, nil, "", clusterAPIErr(err)
	}
	return archive, files, m, signer, nil
}

func pluginCapabilities(m *clusterx.Manifest) []map[string]string {
	out := []map[string]string{}
	for _, p := range m.Permissions {
		out = append(out, map[string]string{"permission": p, "description": clusterx.Permissions[p]})
	}
	return out
}

func (s *Server) pluginInspect(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	_, files, m, signer, err := s.pluginLoad(r)
	if err != nil {
		return nil, err
	}
	var exists bool
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT 1 FROM plugins WHERE name=?`, m.Name).Scan(&exists)
	return map[string]any{"manifest": m, "signer": signer, "files": len(files), "capabilities": pluginCapabilities(m), "upgrade": exists}, nil
}

func (s *Server) pluginInstall(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	archive, files, m, signer, err := s.pluginLoad(r)
	if err != nil {
		s.audit(r, "plugin.install", "", "rejected", false)
		return nil, err
	}
	if old, err := s.pluginByName(r.Context(), m.Name); err == nil && old.Enabled {
		return nil, conflict("plugin_exists") // disable first, then upgrade
	}
	var out rpc.PluginResult
	if err := s.agentCall(r, rpc.MPluginInstall, rpc.PluginInstallReq{Name: m.Name, Archive: archive}, &out); err != nil {
		s.audit(r, "plugin.install", m.Name, nsAgentCode(err), false)
		return nil, err
	}
	mj, _ := json.Marshal(m)
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO plugins(name,version,author,license,manifest_json,signer,enabled,webhook_ids,installed_at)
		VALUES(?,?,?,?,?,?,0,'[]',?) ON CONFLICT(name) DO UPDATE SET version=excluded.version, author=excluded.author, license=excluded.license,
		manifest_json=excluded.manifest_json, signer=excluded.signer, installed_at=excluded.installed_at`,
		m.Name, m.Version, m.Author, m.License, string(mj), signer, s.Now().Unix()); err != nil {
		return nil, err
	}
	s.audit(r, "plugin.install", m.Name+"@"+m.Version, "signer "+signer, true)
	return map[string]any{"name": m.Name, "version": m.Version, "files": len(files), "signer": signer, "path": out.Path,
		"capabilities": pluginCapabilities(m)}, nil
}

// pluginHooksOff deletes the webhook rows a plugin registered.
func (s *Server) pluginHooksOff(ctx context.Context, x pluginRow) {
	for _, id := range x.WebhookIDs {
		s.Store.DB.ExecContext(ctx, `DELETE FROM webhooks WHERE id=? AND name LIKE 'plugin:%'`, id)
		_ = s.Secrets().Delete(ctx, secretName(id))
	}
	s.Store.DB.ExecContext(ctx, `UPDATE plugins SET webhook_ids='[]' WHERE name=?`, x.Name)
}

func (s *Server) pluginEnable(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	x, err := s.pluginByName(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return nil, err
	}
	var in PluginEnableReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if !in.Enabled {
		s.pluginHooksOff(r.Context(), x)
		s.Store.DB.ExecContext(r.Context(), `UPDATE plugins SET enabled=0 WHERE name=?`, x.Name)
		s.audit(r, "plugin.disable", x.Name, "", true)
		return map[string]any{"enabled": false}, nil
	}
	if x.Enabled {
		return map[string]any{"enabled": true}, nil
	}
	if err := x.Manifest.Validate(nil); err != nil { // allowlists may have shrunk since install
		return nil, clusterAPIErr(err)
	}
	if len(x.Manifest.Hooks) > 0 && s.Secrets().Status()["status"] != "ok" {
		return nil, errSecretsUnavailable
	}
	ids := []int64{}
	for i, h := range x.Manifest.Hooks {
		ev, err := normEvents(h.Events)
		if err == nil {
			err = s.checkWebhookURL(r.Context(), h.URL)
		}
		if err == nil {
			var res sql.Result
			res, err = s.Store.DB.ExecContext(r.Context(), `INSERT INTO webhooks(name,url,secret,events,enabled,created_at) VALUES(?,?,'',?,1,?)`,
				fmt.Sprintf("plugin:%s:%d", x.Name, i+1), h.URL, ev, s.Now().Unix())
			if err == nil {
				id, _ := res.LastInsertId()
				ids = append(ids, id)
				if err = s.Secrets().Put(r.Context(), secretName(id), []byte(newWebhookSecret())); err == nil {
					s.Store.DB.ExecContext(r.Context(), `UPDATE webhooks SET secret=? WHERE id=?`, "secret:"+secretName(id), id)
				}
			}
		}
		if err != nil {
			x.WebhookIDs = ids
			s.pluginHooksOff(r.Context(), x)
			s.audit(r, "plugin.enable", x.Name, "hook_rejected", false)
			return nil, err
		}
	}
	wj, _ := json.Marshal(ids)
	s.Store.DB.ExecContext(r.Context(), `UPDATE plugins SET enabled=1, webhook_ids=? WHERE name=?`, string(wj), x.Name)
	s.audit(r, "plugin.enable", x.Name, fmt.Sprintf("%d hook(s)", len(ids)), true)
	return map[string]any{"enabled": true, "webhooks": ids}, nil
}

func (s *Server) pluginRemove(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	x, err := s.pluginByName(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MPluginRemove, rpc.PluginRemoveReq{Name: x.Name}, nil); err != nil {
		s.audit(r, "plugin.remove", x.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.pluginHooksOff(r.Context(), x)
	s.Store.DB.ExecContext(r.Context(), `DELETE FROM plugins WHERE name=?`, x.Name)
	s.audit(r, "plugin.remove", x.Name, "", true)
	return nil, nil
}

func (s *Server) pluginKeyAdd(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	var in PluginKeyReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return nil, bad("invalid_name")
	}
	pk, err := clusterx.ParsePublicKey(in.PubKey)
	if err != nil {
		return nil, clusterAPIErr(err)
	}
	enc := base64.StdEncoding.EncodeToString(pk)
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO plugin_keys(name,pubkey,key_id,created_at) VALUES(?,?,?,?) ON CONFLICT(pubkey) DO NOTHING`,
		in.Name, enc, clusterx.KeyID(pk), s.Now().Unix())
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, conflict("already_exists")
	}
	id, _ := res.LastInsertId()
	s.audit(r, "plugin.key.add", in.Name+" "+clusterx.KeyID(pk), "", true)
	return map[string]any{"id": id, "key_id": clusterx.KeyID(pk)}, nil
}

func (s *Server) pluginKeyDel(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := clusterAdminOnly(r); err != nil {
		return nil, err
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM plugin_keys WHERE id=?`, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	s.audit(r, "plugin.key.remove", strconv.FormatInt(idParam(r, "id"), 10), "", true)
	return nil, nil
}

// pluginAsset serves a file below <PluginRoot>/<name>/ui/ of an enabled
// plugin. The response is sandboxed (opaque origin: no cookies, no panel
// API with the admin's session) and only framable by the panel itself.
func (s *Server) pluginAsset(w http.ResponseWriter, r *http.Request) {
	fail := func() { writeJSON(w, 404, apiError{Code: "not_found"}) }
	if clusterAdminOnly(r) != nil {
		writeJSON(w, 403, apiError{Code: "forbidden"})
		return
	}
	x, err := s.pluginByName(r.Context(), chi.URLParam(r, "name"))
	if err != nil || !x.Enabled {
		fail()
		return
	}
	rel := chi.URLParam(r, "*")
	if rel == "" || !clusterx.ValidRelPath(rel) {
		fail()
		return
	}
	base := filepath.Join(PluginRoot, x.Name, "ui")
	p := filepath.Join(base, filepath.FromSlash(rel))
	if !strings.HasPrefix(p, base+string(os.PathSeparator)) {
		fail()
		return
	}
	// refuse symlinks anywhere below the plugin directory
	for cur := p; cur != filepath.Dir(base); cur = filepath.Dir(cur) {
		if st, err := os.Lstat(cur); err != nil || st.Mode()&os.ModeSymlink != 0 {
			fail()
			return
		}
	}
	f, err := os.Open(p)
	if err != nil {
		fail()
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		fail()
		return
	}
	ct := mime.TypeByExtension(path.Ext(rel))
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox allow-scripts allow-forms; default-src 'self' 'unsafe-inline' data:; connect-src 'none'; frame-ancestors 'self'")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", st.ModTime(), f)
}
