import http.server
import gzip
import json
from pathlib import Path
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

CLIENT = str(Path(sys.argv.pop(1)).resolve())


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body, headers=()):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path in ('/bad-gzip-error', '/bad-gzip-ok'):
            if self.path == '/bad-gzip-ok':
                # The next request is a POST on a fresh connection.
                self.server.drop_next_handshake = True
            self.reply(405 if self.path.endswith('error') else 200, {'not': 'gzip'}, [('Content-Encoding', 'gzip')])
        elif self.path in ('/compressed', '/compressed-large'):
            raw = gzip.compress(b'{"compressed":"ok"}' if self.path == '/compressed' else b' ' * 100000)
            self.send_response(200); self.send_header('Content-Encoding', 'gzip')
            self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
        elif self.path == '/cookie/import':
            self.reply(200 if 'imported=value' in self.headers.get('Cookie', '') else 401, {'import': True})
        elif self.path == '/cookie/set':
            self.reply(200, {'set': True}, [('Set-Cookie', 'session=abc123; Path=/; HttpOnly')])
        elif self.path == '/cookie/check':
            if 'session=abc123' in self.headers.get('Cookie', ''):
                self.reply(200, {'cookie': 'yes'})
            else:
                self.reply(401, {'cookie': 'missing'})
        else:
            self.reply(404, {})

    def do_POST(self):
        if self.path == '/disconnect-upload':
            self.server.interrupted_uploads += 1
            self.rfile.read(4096)
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path == '/bad-gzip-error':
            return self.reply(405, {'not': 'gzip'}, [('Content-Encoding', 'gzip')])
        if self.path == '/form' and self.headers.get('X-Fixture') == 'token' and \
                self.headers.get('Content-Type') == 'application/x-www-form-urlencoded' and raw == b'a=1&b=two':
            self.reply(200, {'header': 'token', 'form': raw.decode()})
        else:
            self.reply(400, {'received': raw.decode()})


class Server(http.server.ThreadingHTTPServer):
    drop_next_handshake = True
    dropped_handshakes = 0
    interrupted_uploads = 0

    def get_request(self):
        conn, address = super().get_request()
        if self.drop_next_handshake:
            self.drop_next_handshake = False
            self.dropped_handshakes += 1
            with conn:
                conn.settimeout(2)
                conn.recv(4096)
            raise OSError('fixture dropped the connection before TLS')
        try:
            return self.tls.wrap_socket(conn, server_side=True), address
        except OSError:
            conn.close()
            raise


class Features(unittest.TestCase):
    def test_cookie_jar_headers_and_form(self):
        with tempfile.TemporaryDirectory(prefix='bcontrol-http-') as directory:
            root = Path(directory)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key'),
                            '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
            server = Server(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'cert', root / 'key')
            server.tls = context
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            try:
                result = subprocess.run([CLIENT, 'https://127.0.0.1:' + str(server.server_port), str(root / 'cert')],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                row = json.loads(result.stdout)
                self.assertEqual((row['status'], row['http_status'], row['cookie']), ('ok', 200, True))
                self.assertEqual(server.dropped_handshakes, 2)
                self.assertEqual(server.interrupted_uploads, 3)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == '__main__':
    unittest.main(verbosity=2)
