package api

import (
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// Every route is registered through op(), which records it for the
// generated OpenAPI 3.1 document served at /openapi.json.

type opInfo struct {
	Method, Path, Tag, Summary string
	Body                       any
}

var opsMu sync.Mutex

func (s *Server) op(r chi.Router, method, path, tag, summary string, body any, h http.HandlerFunc) {
	r.Method(method, path, s.featureGate(method, path, h))
	opsMu.Lock()
	defer opsMu.Unlock()
	for _, o := range s.ops {
		if o.Method == method && o.Path == path {
			return
		}
	}
	s.ops = append(s.ops, opInfo{method, path, tag, summary, body})
}

var reParam = regexp.MustCompile(`\{([a-z_]+)\}`)

// versioned are the admin edits with optimistic locking (R2-PERF-15).
var versioned = map[string]bool{
	"PUT /admin/packages/{id}": true, "PUT /admin/accounts/{id}/package": true,
	"POST /admin/accounts/{id}/suspend": true, "POST /admin/accounts/{id}/unsuspend": true,
}

func pageQuery(extra ...map[string]any) []any {
	ps := []any{
		map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000}, "description": "page size; omitted = every row"},
		map[string]any{"name": "offset", "in": "query", "schema": map[string]any{"type": "integer", "minimum": 0}},
		map[string]any{"name": "q", "in": "query", "schema": map[string]any{"type": "string"}, "description": "case-insensitive substring filter"},
	}
	for _, e := range extra {
		ps = append(ps, e)
	}
	return ps
}

var limitType = reflect.TypeOf(Limit{})

func schemaOf(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == limitType {
		return map[string]any{"$ref": "#/components/schemas/Limit"}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaOf(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem())}
	case reflect.Struct:
		props := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "-" || !f.IsExported() {
				continue
			}
			if tag == "" {
				tag = f.Name
			}
			props[tag] = schemaOf(f.Type)
		}
		return map[string]any{"type": "object", "properties": props}
	}
	return map[string]any{}
}

func opID(method, path string) string {
	p := reParam.ReplaceAllString(path, "by_$1")
	p = strings.NewReplacer("/", "_", "-", "_").Replace(strings.Trim(p, "/"))
	return strings.ToLower(method) + "_" + p
}

func errResp(desc string) map[string]any {
	return map[string]any{"description": desc, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}}
}

// opResponses lists the status codes a route really returns (CODE-22).
func opResponses(o opInfo) map[string]any {
	ok := map[string]any{"description": "OK", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}
	if o.Path == "/user/files/download" {
		ok = map[string]any{"description": "File content", "content": map[string]any{"application/octet-stream": map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}}
	}
	rs := map[string]any{
		"200": ok,
		"400": errResp("Invalid input (error code names the field rule)"),
		"429": errResp("Rate limited or too many failed attempts"),
		"500": errResp("Internal error (message carries only a request id)"),
	}
	if o.Method != "GET" {
		rs["403"] = errResp("Forbidden, bad Origin/Sec-Fetch-Site or missing/invalid X-CSRF-Token")
	}
	if o.Tag == "auth" {
		rs["401"] = errResp("Invalid credentials, TOTP code or token")
		if o.Method == "POST" {
			rs["415"] = errResp("Unauthenticated POST must be application/json")
		}
		return rs
	}
	rs["401"] = errResp("Not logged in")
	rs["403"] = errResp("Forbidden (role, ownership, reserved name), bad Origin or CSRF token")
	rs["404"] = errResp("Not found (or not owned by the caller)")
	rs["405"] = errResp("Method not allowed")
	if o.Method != "GET" {
		rs["409"] = errResp("Conflict: already exists, limit reached, name owned by another account, account busy")
		rs["422"] = errResp("Valid input that cannot be applied (e.g. not a directory, reserved name)")
	}
	if o.Tag != "account" && o.Tag != "packages" {
		rs["502"] = errResp("The root agent could not perform the action")
		rs["503"] = errResp("The root agent is unreachable")
		rs["504"] = errResp("The root agent did not answer in time")
	}
	if o.Tag == "files" {
		rs["413"] = errResp("File too large")
	}
	if o.Method != "GET" {
		rs["507"] = errResp("disk_full (server disk) or quota_exceeded (account quota)")
	}
	rs["503"] = errResp("agent_unreachable (agent down or circuit open), server_busy (password hashing / upload slots full; see Retry-After) or db_busy")
	if versioned[o.Method+" "+o.Path] {
		rs["412"] = errResp("version_conflict: the row changed since it was read (If-Match / version); the current version is in ETag")
	}
	return rs
}

// contractNotes documents the round-2 contract (for the UI and API users).
const contractNotes = `Contract notes (v0.2 round 2):
- Limits (G1): every limit uses -1 (or null) = unlimited, 0 = none, n > 0 = at most n (schema Limit). Size limits (disk_mb, bandwidth_mb, mail_quota_mb, memory_mb, cpu_percent, max_tasks, quota_mb, reseller_disk_mb) reject 0. Existing 0 values were migrated to -1. /user/summary stats use limit -1 for unlimited.
- Validation errors carry field (the JSON key) and, for length/limit errors, max. Over-long values are rejected with 400 too_long {field, max}, never truncated. Passwords over 256 bytes: password_too_long {field, max: 256}.
- Domains: trimmed, lower-cased, a trailing dot removed, IDN converted to punycode; schemes/paths, emoji/symbol labels (invalid_idn) and public suffixes such as com.tr (public_suffix) are refused. A domain longer than 128 characters gets a shortened default docroot (returned as docroot).
- Docroot / FTP dir: private_dir for etc, mail, logs, tmp, backups, ssl (and below); too_long over 255 bytes or 128 per segment; invalid_docroot / invalid_path for grammar.
- File Manager: invalid_filename {field: path|dest, max: 255} for names over 255 bytes or "." / "..".
- POST /account/password: a wrong current password answers 400 wrong_current_password {field: current}. TOTP codes accept spaces and dashes ("123 456").
- Paging: GET /admin/accounts and GET /user/dns/{domain} take limit/offset/q (+role/status, +type); totals in X-Total-Count. Without limit the full list is returned.
- Optimistic locking: packages and accounts carry version; PUT /admin/packages/{id}, PUT /admin/accounts/{id}/package, POST .../suspend and .../unsuspend accept If-Match or a version body field and answer 412 version_conflict on a stale edit.
- Resellers: GET /admin/packages lists only the reseller's own packages; using another package answers 403 package_not_owned {field: package_id}; creating a reseller answers 403 reseller_cannot_create_reseller {field: role}; /admin/summary has no "resellers" key for resellers.
- Overload: 503 server_busy (Retry-After) when password hashing or upload slots are full; 503 db_busy when the database is locked; 503 agent_unreachable fails fast while the agent is down or hung; 507 disk_full when the server disk is full (quota_exceeded stays the account quota).`

// OpenAPI returns the spec for both realms.
func (s *Server) OpenAPI() map[string]any {
	paths := map[string]any{}
	opsMu.Lock()
	ops := append([]opInfo(nil), s.ops...)
	opsMu.Unlock()
	sort.Slice(ops, func(i, j int) bool { return ops[i].Path < ops[j].Path })
	userSrv := []any{map[string]any{"url": "https://{host}:2083", "variables": map[string]any{"host": map[string]any{"default": "server.example.com"}}}}
	adminSrv := []any{map[string]any{"url": "https://{host}:2087", "variables": map[string]any{"host": map[string]any{"default": "server.example.com"}}}}
	for _, o := range ops {
		full := "/api/v1" + o.Path
		item, _ := paths[full].(map[string]any)
		if item == nil {
			item = map[string]any{}
			switch {
			case strings.HasPrefix(o.Path, "/user/"):
				item["servers"] = userSrv
			case strings.HasPrefix(o.Path, "/admin/"):
				item["servers"] = adminSrv
			}
			paths[full] = item
		}
		op := map[string]any{"operationId": opID(o.Method, o.Path), "summary": o.Summary, "tags": []string{o.Tag},
			"responses": opResponses(o)}
		var params []any
		for _, m := range reParam.FindAllStringSubmatch(o.Path, -1) {
			typ := map[string]any{"type": "string"}
			if m[1] == "id" || m[1] == "db" || (m[1] == "user" && strings.Contains(o.Path, "db-grants")) {
				typ = map[string]any{"type": "integer", "format": "int64", "minimum": 1}
			}
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": typ})
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		if o.Body != nil {
			op["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaOf(reflect.TypeOf(o.Body))}}}
		}
		if o.Path == "/user/files/upload" {
			op["requestBody"] = map[string]any{"required": true, "content": map[string]any{"multipart/form-data": map[string]any{"schema": map[string]any{
				"type": "object", "required": []string{"path", "file"},
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "target directory relative to the home; must precede the file parts"},
					"file": map[string]any{"type": "array", "items": map[string]any{"type": "string", "format": "binary"}, "description": "one or more files, max 256 MiB each"},
				}}}}}
		}
		if o.Path == "/user/files/download" {
			op["parameters"] = []any{map[string]any{"name": "path", "in": "query", "required": true, "schema": map[string]any{"type": "string"}}}
		}
		switch {
		case o.Method == "GET" && o.Path == "/admin/accounts":
			op["parameters"] = pageQuery(
				map[string]any{"name": "role", "in": "query", "schema": map[string]any{"type": "string", "enum": []string{"user", "reseller"}}},
				map[string]any{"name": "status", "in": "query", "schema": map[string]any{"type": "string", "enum": []string{"active", "suspended", "provisioning", "terminating"}}})
			op["description"] = "Server-side paging (R2-PERF-8). The body is the same JSON array as without paging; the number of matching rows is in the X-Total-Count header. q matches username, primary domain or email. Without limit every row is returned (backward compatible). Each row carries version for If-Match."
		case o.Method == "GET" && o.Path == "/admin/audit":
			op["parameters"] = pageQuery()
			op["description"] = "Newest first; limit defaults to 200. q of 3+ characters uses the full-text (trigram) index, same substring semantics as before. X-Total-Count = matching rows (cached up to 10 s)."
		case o.Method == "GET" && o.Path == "/user/dns/{domain}":
			op["parameters"] = append([]any{map[string]any{"name": "domain", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
				pageQuery(map[string]any{"name": "type", "in": "query", "schema": map[string]any{"type": "string", "enum": []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS"}}})...)
			op["description"] = "Server-side paging of records (R2-PERF-8). The response is the zone object as before ({zone, records, serial}) plus total (matching records), offset and limit (-1 = all); X-Total-Count = total. q matches record name or content. Without limit every record is returned."
		case o.Method == "PUT" && o.Path == "/user/dns/{domain}/rrset":
			op["description"] = "name: \"\" or \"@\" = apex; a relative name (www) is placed in the zone; a name with a trailing dot is absolute (FQDN) and must lie inside the zone, else 400 record_outside_zone (R2-UX-18). IDN labels are converted to punycode."
		}
		if versioned[o.Method+" "+o.Path] {
			ps, _ := op["parameters"].([]any)
			op["parameters"] = append(ps, map[string]any{"name": "If-Match", "in": "header", "schema": map[string]any{"type": "string"},
				"description": "optional: the row's version (\"3\", W/\"3\" or 3) as read; a mismatch answers 412 version_conflict. The JSON body field version does the same."})
		}
		if o.Tag != "auth" || o.Path == "/auth/me" || o.Path == "/auth/logout" {
			op["security"] = []any{map[string]any{"session": []string{}, "csrf": []string{}}}
		}
		item[strings.ToLower(o.Method)] = op
	}
	paths["/openapi.json"] = map[string]any{"get": map[string]any{"operationId": "get_openapi", "summary": "This document", "tags": []string{"meta"},
		"responses": map[string]any{"200": map[string]any{"description": "OpenAPI 3.1 document", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}}}}
	paths["/internal/pma-token/{token}"] = map[string]any{"servers": userSrv, "get": map[string]any{"operationId": "get_internal_pma_token", "tags": []string{"internal"},
		"summary":    "Loopback only: phpMyAdmin signon script exchanges a one-time token for MariaDB credentials",
		"parameters": []any{map[string]any{"name": "token", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
		"responses":  map[string]any{"200": map[string]any{"description": "Credentials"}, "403": errResp("Not from loopback"), "404": errResp("Invalid, used or expired token")}}}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{"title": "BOZKURT PANEL API", "version": s.Version, "license": map[string]any{"name": "Apache-2.0", "identifier": "Apache-2.0"},
			"description": "User-panel endpoints (/user/*) are served on port 2083; admin endpoints (/admin/*) on port 2087. State-changing requests need the X-CSRF-Token header returned by /auth/login or /auth/me. Every response carries X-Request-ID; 5xx bodies contain only that id. /3rdparty/phpMyAdmin/* is a reverse proxy to phpMyAdmin (not part of the API).\n\n" + contractNotes},
		"servers": append(append([]any{}, userSrv...), adminSrv...),
		"paths":   paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"session": map[string]any{"type": "apiKey", "in": "cookie", "name": "bp_user_session", "description": "bp_user_session on 2083, bp_admin_session on 2087"},
				"csrf":    map[string]any{"type": "apiKey", "in": "header", "name": "X-CSRF-Token"},
			},
			"schemas": map[string]any{
				"Error": map[string]any{"type": "object", "required": []string{"error"}, "properties": map[string]any{
					"error":   map[string]any{"type": "string", "description": "machine-readable code", "enum": ErrorCodes},
					"message": map[string]any{"type": "string"},
					"field":   map[string]any{"type": "string", "description": "request field (JSON key) the error is about, for inline display"},
					"max":     map[string]any{"type": "integer", "description": "too_long: the field's maximum length in bytes; invalid_limit: the largest accepted value; password_too_long: 256"},
					"step":    map[string]any{"type": "string", "enum": []string{"db", "user", "grant"}, "description": "db-wizard: the step that failed"}}},
				"Limit": map[string]any{"type": []string{"integer", "null"}, "minimum": -1,
					"description": "G1 limit: -1 or null = unlimited, 0 = none (count limits only; size limits such as *_mb, cpu_percent and max_tasks reject 0 with invalid_limit), n > 0 = at most n. Absent in a request = unlimited (mailbox quota_mb: the package's mail_quota_mb). Responses always use -1 for unlimited."},
				"Warning": map[string]any{"type": "object", "required": []string{"code", "area"}, "description": "Non-blocking notice in a 2xx body (warnings: [])",
					"properties": map[string]any{"code": map[string]any{"type": "string", "enum": WarningCodes},
						"area": map[string]any{"type": "string", "enum": []string{"mail", "dns", "web", "db", "ftp", "quota", "settings", "account"}}, "detail": map[string]any{"type": "string"}}},
				"AuditRealm": map[string]any{"type": "string", "enum": AuditRealms, "description": "realm column of audit rows (handoff-ui H-9)"},
				"ServiceActiveState": map[string]any{"type": "string", "enum": []string{"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "unknown"},
					"description": "systemd ActiveState; unknown when the agent runs without systemd (handoff-ui H-11)"},
			},
			"responses": map[string]any{"Error": errResp("Error")},
		},
	}
}
