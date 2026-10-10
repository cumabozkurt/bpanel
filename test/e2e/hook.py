# Minimal webhook receiver for the E2E: appends each delivery as one JSON line.
import http.server, json, sys
OUT = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        rec = {k: v for k, v in self.headers.items() if k.lower().startswith('x-bpanel')}
        rec['body'] = b.decode()
        with open(OUT, 'a') as f: f.write(json.dumps(rec) + '\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
