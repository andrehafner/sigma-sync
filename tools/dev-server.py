#!/usr/bin/env python3
"""Local development server for Sigma Sync (never use in production).

Serves the static files and runs api.pl as a CGI script, so the app can be tried
without Apache:

    APP_ENV_FILE=/path/to/dev.env python3 tools/dev-server.py [port]

Put COOKIE_SECURE=0 and COOKIE_PATH=/ in the dev env file (plain HTTP on localhost).
"""
import http.server
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = {'index.html', 'app.js', 'style.css', 'favicon.svg'}
# Same policy as deploy/sigmasync.conf, so CSP problems show up during development.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self' https://api.github.com https://api.ergoplatform.com; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def _allowed(self):
        path = self.path.split('?', 1)[0].lstrip('/')
        return path == '' or path in STATIC or path.startswith('vendor/')

    def end_headers(self):
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('Cache-Control', 'no-cache')
        super().end_headers()

    def do_GET(self):
        if not self._allowed():
            self.send_error(404)
            return
        super().do_GET()

    def do_POST(self):
        if self.path.split('?', 1)[0] != '/api.pl':
            self.send_error(404)
            return
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length)
        env = dict(os.environ,
                   GATEWAY_INTERFACE='CGI/1.1', REQUEST_METHOD='POST', SCRIPT_NAME='/api.pl',
                   CONTENT_TYPE=self.headers.get('Content-Type', ''), CONTENT_LENGTH=str(length),
                   HTTP_COOKIE=self.headers.get('Cookie', ''), REMOTE_ADDR=self.client_address[0],
                   SERVER_NAME='localhost', SERVER_PORT=str(self.server.server_port),
                   SERVER_PROTOCOL='HTTP/1.1', HTTPS='off')
        proc = subprocess.run(['perl', os.path.join(ROOT, 'api.pl')], input=body, env=env,
                              capture_output=True, cwd=ROOT)
        if proc.stderr:
            sys.stderr.write(proc.stderr.decode('utf-8', 'replace'))
        head, _, payload = proc.stdout.partition(b'\r\n\r\n')
        self.send_response(200)
        for line in head.decode('latin-1').split('\r\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                if key.lower() != 'status':
                    self.send_header(key.strip(), value.strip())
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f'Sigma Sync dev server on http://127.0.0.1:{port}/')
    http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
