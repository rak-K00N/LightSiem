"""Stage 5: web dashboard + JSON API (standard library only)."""
import json, os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

STATIC = os.path.join(os.path.dirname(__file__), '..', 'static')


def make_handler(store):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype='application/json', code=200):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            p = {k: v[0] for k, v in parse_qs(u.query).items()}
            num = lambda k: int(p[k]) if p.get(k, '').lstrip('-').isdigit() else None
            try:
                if u.path == '/':
                    return self._send(open(os.path.join(STATIC, 'index.html'), 'rb').read(), 'text/html; charset=utf-8')
                if u.path == '/api/stats':
                    return self._send(store.stats())
                if u.path == '/api/alerts':
                    return self._send(store.alerts(num('limit') or 100))
                if u.path == '/api/events':
                    return self._send({'count': store.count(p.get('q'), p.get('ip'), p.get('category'), num('t0'), num('t1'), p.get('severity')),
                                       'events': store.search(p.get('q'), p.get('ip'), p.get('category'), num('t0'), num('t1'), p.get('severity'), min(num('limit') or 100, 1000))})
                if u.path == '/api/timeline':
                    return self._send(store.timeline(num('bucket') or 60, num('t0'), num('t1')))
                if u.path == '/api/top_ips':
                    return self._send(store.top_ips(p.get('category'), num('limit') or 10))
            except Exception as ex:  # never crash the server on a bad query
                return self._send({'error': str(ex)}, code=400)
            self._send({'error': 'not found'}, code=404)
    return H


def serve(store, port=8080, host='127.0.0.1'):
    srv = ThreadingHTTPServer((host, port), make_handler(store))
    print(f'LightSIEM dashboard: http://{host}:{port}')
    srv.serve_forever()
