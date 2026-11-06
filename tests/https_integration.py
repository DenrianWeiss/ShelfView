import base64
import datetime
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings

AGENT = str(Path(sys.argv.pop(1)).resolve())


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == '/slow':
            time.sleep(1)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'https://different.invalid/redfish/v1/')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if self.path == '/auth' and self.headers.get('Authorization') != 'Basic ' + base64.b64encode(b'test:dummy-test-password').decode():
            status, body = 401, b'{"error":"unauthorized"}'
        else:
            status = 404 if self.path == '/missing' else 200
            body = (b'x' * 4096 if self.path == '/large' else json.dumps({
                '@odata.id': '/redfish/v1/', 'RedfishVersion': '1.17.0',
                'Systems': {'@odata.id': '/redfish/v1/Systems'},
                'UUID': 'simulated-test-endpoint',
            }).encode())
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='bcontrol-integration-')
        cls.root = Path(cls.temp.name)
        cls.servers = []

        def openssl(*args):
            subprocess.run(['openssl', *args], cwd=cls.root, check=True, capture_output=True)

        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=bControl integration CA')
        (cls.root / 'newcerts').mkdir()
        (cls.root / 'index.txt').write_text('')
        (cls.root / 'index.txt.attr').write_text('unique_subject = no\n')
        (cls.root / 'serial').write_text('1000\n')
        (cls.root / 'ca.conf').write_text('[ ca ]\ndefault_ca = local\n[ local ]\ndatabase = index.txt\nserial = serial\nnew_certs_dir = newcerts\ncertificate = ca.crt\nprivate_key = ca.key\ndefault_md = sha256\ndefault_days = 1\npolicy = names\ncopy_extensions = copy\n[ names ]\ncommonName = supplied\n')
        now = datetime.datetime.now(datetime.timezone.utc)
        for name, hostname in [('valid', 'localhost'), ('expired', 'localhost'), ('wrong', 'different.invalid')]:
            openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr', '-subj', '/CN=' + hostname, '-addext', 'subjectAltName=DNS:' + hostname)
            args = ['ca', '-batch', '-notext', '-config', 'ca.conf', '-in', name + '.csr', '-out', name + '.crt']
            if name == 'expired':
                args += ['-startdate', (now - datetime.timedelta(days=2)).strftime('%Y%m%d%H%M%SZ'), '-enddate', (now - datetime.timedelta(days=1)).strftime('%Y%m%d%H%M%SZ')]
            openssl(*args)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'untrusted.key', '-out', 'untrusted.crt', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')

    @classmethod
    def tearDownClass(cls):
        for server, thread in cls.servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        cls.temp.cleanup()

    @classmethod
    def server(cls, name='valid', version=None):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.root / (name + '.crt'), cls.root / (name + '.key'))
        if version is not None:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                ctx.minimum_version = ctx.maximum_version = version
            if version < ssl.TLSVersion.TLSv1_2:
                ctx.set_ciphers('AES128-SHA:@SECLEVEL=0')
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        thread.start()
        cls.servers.append((server, thread))
        return 'https://localhost:' + str(server.server_port)

    def inspect(self, origin, *options, credentials=False):
        env = os.environ.copy()
        env.pop('BC_BMC_USERNAME', None)
        env.pop('BC_BMC_PASSWORD', None)
        if credentials:
            env.update(BC_BMC_USERNAME='test', BC_BMC_PASSWORD='dummy-test-password')
        p = subprocess.run([AGENT, 'inspect', '--endpoint', origin, '--ca', str(self.root / 'ca.crt'), *options], env=env, text=True, capture_output=True, timeout=8)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return json.loads(p.stdout)

    def test_certificate_modes_and_pool_isolation(self):
        for name in ('valid', 'expired', 'wrong', 'untrusted'):
            origin = self.server(name)
            for mode in ('strict', 'skip-chain', 'skip-all'):
                with self.subTest(certificate=name, mode=mode):
                    row = self.inspect(origin, '--cert-policy', mode)[0]
                    success = name == 'valid' or mode == 'skip-all' or (mode == 'skip-chain' and name != 'wrong')
                    self.assertEqual(row['status'], 'ok' if success else 'tls_error', row)
                    self.assertEqual(row['verification'], 'verified' if success and mode == 'strict' else 'not_verified')
                    if success:
                        self.assertIn(row['tls_version'], ('TLSv1.2', 'TLSv1.3'))
                        self.assertEqual(row['body']['UUID'], 'simulated-test-endpoint')
            if name != 'valid':
                rows = self.inspect(origin, '--cert-policy', 'skip-all', '--then-strict')
                self.assertEqual([r['status'] for r in rows], ['ok', 'tls_error'])
                self.assertNotEqual(rows[0]['endpoint_revision'], rows[1]['endpoint_revision'])

    def test_tls_versions(self):
        for text, version in [('1.0', ssl.TLSVersion.TLSv1), ('1.1', ssl.TLSVersion.TLSv1_1)]:
            with self.subTest(version=text):
                origin = self.server(version=version)
                self.assertEqual(self.inspect(origin)[0]['status'], 'tls_error')
                row = self.inspect(origin, '--tls-min', text, '--tls-max', text)[0]
                self.assertEqual(row['status'], 'ok', row)
                self.assertEqual(row['verification'], 'verified')
                self.assertEqual(row['tls_version'], 'TLSv1' if text == '1.0' else 'TLSv1.1')

    def test_authentication_http_errors_and_redirect(self):
        origin = self.server()
        self.assertEqual(self.inspect(origin, '--path', '/auth')[0]['http_status'], 401)
        self.assertEqual(self.inspect(origin, '--path', '/auth', credentials=True)[0]['status'], 'ok')
        self.assertEqual(self.inspect(origin, '--path', '/missing')[0]['status'], 'http_error')
        row = self.inspect(origin, '--path', '/redirect')[0]
        self.assertEqual(row['http_status'], 302)

    def test_response_limit_and_timeout(self):
        origin = self.server()
        self.assertEqual(self.inspect(origin, '--path', '/large', '--max-response', '128')[0]['status'], 'limit_exceeded')
        self.assertEqual(self.inspect(origin, '--path', '/slow', '--timeout-ms', '100')[0]['status'], 'timeout')

    def test_logging_gates_and_redaction(self):
        origin = self.server()
        env = os.environ.copy()
        env.update(BC_BMC_USERNAME='test', BC_BMC_PASSWORD='dummy-test-password')
        base = [AGENT, 'inspect', '--log-level', 'debug', '--log-categories', 'http,tls', '--endpoint', origin,
                '--ca', str(self.root / 'ca.crt')]
        p = subprocess.run(base, env=env, text=True, capture_output=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)[0]['status'], 'ok')
        self.assertIn('level=debug category=http', p.stderr)
        self.assertIn('event=request.complete', p.stderr)
        self.assertNotIn('dummy-test-password', p.stderr)
        self.assertNotIn('localhost', p.stderr)
        self.assertNotIn('category=lifecycle', p.stderr)

        off = [AGENT, '--log-level', 'off', 'inspect', '--endpoint', origin, '--ca', str(self.root / 'ca.crt')]
        p = subprocess.run(off, env=env, text=True, capture_output=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, '')

        verbose = [AGENT, '--log-level', 'verbose', '--log-categories', 'redfish,http,tls', 'inspect',
                   '--endpoint', origin, '--ca', str(self.root / 'ca.crt')]
        p = subprocess.run(verbose, env=env, text=True, capture_output=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)[0]['status'], 'ok')
        self.assertNotIn('dummy-test-password', p.stderr)

        bad = subprocess.run([AGENT, '--log-level', 'bogus', 'inspect'], text=True, capture_output=True)
        self.assertEqual(bad.returncode, 2)
        self.assertIn('unknown log level', bad.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
