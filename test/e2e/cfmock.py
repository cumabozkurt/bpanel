# Local stand-in for the Cloudflare v4 API (only the calls BPANEL makes).
# Lets the E2E exercise link/verify/detect/sync end to end without a real account.
import http.server, json, sys, re, urllib.parse
TOKEN = sys.argv[2]; ZONE = sys.argv[3]; LOG = sys.argv[4]
records = [{"id": "r0", "type": "A", "name": ZONE, "content": "192.0.2.1", "ttl": 1}]
def ok(res, info=None):
    d = {"success": True, "errors": [], "messages": [], "result": res}
    if info: d["result_info"] = info
    return d
class H(http.server.BaseHTTPRequestHandler):
    def _auth(self):
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            self._send(403, {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}], "result": None}); return False
        return True
    def _send(self, code, d):
        b = json.dumps(d).encode(); self.send_response(code)
        self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(b)
    def _log(self, body=''):
        with open(LOG, 'a') as f: f.write(json.dumps({"m": self.command, "p": self.path, "b": body}) + "\n")
    def do_GET(self):
        self._log()
        if not self._auth(): return
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path.endswith('/user/tokens/verify'): return self._send(200, ok({"id": "t1", "status": "active"}))
        if u.path.endswith('/zones'):
            n = q.get('name', [''])[0]
            z = [{"id": "z1", "name": ZONE, "status": "active", "name_servers": ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]}] if n in ('', ZONE) else []
            return self._send(200, ok(z, {"page": 1, "per_page": 50, "count": len(z), "total_count": len(z), "total_pages": 1}))
        if re.search(r'/zones/z1/dns_records$', u.path):
            return self._send(200, ok(records, {"page": 1, "per_page": 100, "count": len(records), "total_count": len(records), "total_pages": 1}))
        self._send(404, {"success": False, "errors": [{"code": 7003, "message": "not found"}], "result": None})
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode(); self._log(b)
        if not self._auth(): return
        if re.search(r'/zones/z1/dns_records$', self.path):
            r = json.loads(b); r["id"] = "r%d" % len(records); records.append(r); return self._send(200, ok(r))
        self._send(404, {"success": False, "errors": [{"code": 7003, "message": "not found"}], "result": None})
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
