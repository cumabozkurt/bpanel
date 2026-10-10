#!/usr/bin/env python3
"""Minimal stdlib WebSocket client for the BPANEL terminal (E2E only).
usage: wsterm.py <cookie-jar> <https://host:port> <expected-user>
Opens /api/v1/user/terminal/ws with the session cookie, runs `id -un` and an
arithmetic echo in the account's shell and checks both answers."""
import base64, json, os, socket, ssl, struct, sys, time

jar, base, want = sys.argv[1], sys.argv[2].rstrip('/'), sys.argv[3]
host, port = base.split('://', 1)[1].split(':')
cookies = []
for line in open(jar):
    if line.startswith('#HttpOnly_'):
        line = line[len('#HttpOnly_'):]
    elif line.startswith('#') or not line.strip():
        continue
    f = line.rstrip('\n').split('\t')
    if len(f) == 7:
        cookies.append(f[5] + '=' + f[6])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((host, int(port)), timeout=20), server_hostname=host)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(('GET /api/v1/user/terminal/ws?cols=100&rows=30 HTTP/1.1\r\nHost: %s:%s\r\nUpgrade: websocket\r\n'
           'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nOrigin: %s\r\nCookie: %s\r\n\r\n'
           % (host, port, key, base, '; '.join(cookies))).encode())
resp = b''
while b'\r\n\r\n' not in resp:
    resp += s.recv(4096)
head, rest = resp.split(b'\r\n\r\n', 1)
if b' 101 ' not in head.split(b'\r\n')[0]:
    print('handshake:', head.split(b'\r\n')[0].decode(), rest[:200]); sys.exit(1)

def send(obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    hdr = bytes([0x81]) + (bytes([0x80 | len(data)]) if len(data) < 126 else bytes([0x80 | 126]) + struct.pack('>H', len(data)))
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

buf = rest
def frames():
    global buf
    while True:
        while len(buf) < 2:
            buf += s.recv(65536)
        n = buf[1] & 0x7f; off = 2
        if n == 126:
            while len(buf) < 4: buf += s.recv(65536)
            n = struct.unpack('>H', buf[2:4])[0]; off = 4
        elif n == 127:
            while len(buf) < 10: buf += s.recv(65536)
            n = struct.unpack('>Q', buf[2:10])[0]; off = 10
        while len(buf) < off + n:
            buf += s.recv(65536)
        op, payload, buf = buf[0] & 0x0f, buf[off:off + n], buf[off + n:]
        if op == 8:
            return
        yield payload

send({'t': 'r', 'c': 100, 'r': 30})
send({'t': 'i', 'd': 'id -un; echo BPWS-$((6*7)); pwd\n'})
out, deadline = b'', time.time() + 20
for p in frames():
    out += p
    if b'BPWS-42' in out.replace(b'BPWS-$((6*7))', b'') or time.time() > deadline:
        break
time.sleep(0.5)
text = out.decode('utf-8', 'replace')
print(text[-600:])
ok = 'BPWS-42' in text.replace('BPWS-$((6*7))', '') and want in text
send({'t': 'i', 'd': 'exit\n'})
sys.exit(0 if ok else 1)
