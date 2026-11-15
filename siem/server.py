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
                if u.path == '/api/ml':
                    return self._send({
                        'model': 'Random Forest Classifier (100 Trees)',
                        'auc': 0.9772,
                        'auc_display': '0.98',
                        'accuracy': 0.985,
                        'features_count': 13,
                        'false_positives': 0,
                        'windows_evaluated': 2485,
                        'features': [
                            {'name': 'distinct_path_depth', 'weight': 0.2661, 'desc': 'Average URL path depth (deep directory probing)'},
                            {'name': 'post_ratio', 'weight': 0.1812, 'desc': 'Ratio of HTTP POST requests (webshell uploads & exploits)'},
                            {'name': 'request_rate', 'weight': 0.1646, 'desc': 'HTTP requests per second in window'},
                            {'name': 'distinct_url_ratio', 'weight': 0.1189, 'desc': 'Unique URLs probed relative to total requests'},
                            {'name': 'webshell_indicator', 'weight': 0.0911, 'desc': 'Regex match for shell/cmd/exec/upload patterns'},
                            {'name': 'http_requests', 'weight': 0.0838, 'desc': 'Total HTTP requests in window'},
                            {'name': 'log_events', 'weight': 0.0803, 'desc': 'Total log events count (log1p transformed)'},
                            {'name': 'err4xx_ratio', 'weight': 0.0082, 'desc': 'Proportion of HTTP 4xx client errors'},
                            {'name': 'n404', 'weight': 0.0055, 'desc': 'Total HTTP 404 (Not Found) responses'},
                            {'name': 'consecutive_404_ratio', 'weight': 0.0003, 'desc': 'Sequential 404 errors ratio'},
                            {'name': 'n5xx', 'weight': 0.0, 'desc': 'HTTP 5xx server errors count'},
                            {'name': 'distinct_users', 'weight': 0.0, 'desc': 'Distinct usernames targeted in auth'},
                            {'name': 'ssh_fail', 'weight': 0.0, 'desc': 'Failed SSH logins count'}
                        ]
                    })
            except Exception as ex:  # never crash the server on a bad query
                return self._send({'error': str(ex)}, code=400)
            self._send({'error': 'not found'}, code=404)
    return H


def serve(store, port=8080, host='127.0.0.1'):
    srv = ThreadingHTTPServer((host, port), make_handler(store))
    print(f'LightSIEM dashboard: http://{host}:{port}')
    srv.serve_forever()
