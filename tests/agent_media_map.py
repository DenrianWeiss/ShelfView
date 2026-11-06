import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

AGENT = str(Path(sys.argv.pop(1)).resolve())
MEDIA_URI = '/redfish/v1/Managers/mgr1/VirtualMedia/cd'
USER, PASSWORD = 'media-user', 'media-password'
PREFIX = 100
LENGTH = 200


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body=None):
        raw = b'' if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        expected = 'Basic ' + base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()
        return self.headers.get('Authorization') == expected

    def do_GET(self):
        if self.path != MEDIA_URI or not self.authorized():
            self.reply(404, {})
            return
        self.reply(200, {'@odata.type': '#VirtualMedia.v1_7_0.VirtualMedia', 'Id': 'cd', 'Name': 'CD',
                         'MediaTypes': ['CD'], 'Inserted': self.server.inserted,
                         'Image': self.server.image, 'Actions': {
                             '#VirtualMedia.InsertMedia': {'target': MEDIA_URI + '/Actions/InsertMedia'},
                             '#VirtualMedia.EjectMedia': {'target': MEDIA_URI + '/Actions/EjectMedia'}}})

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = json.loads(self.rfile.read(length)) if length else None
        if not self.authorized():
            self.reply(404, {})
            return
        if self.path == MEDIA_URI + '/Actions/InsertMedia':
            self.server.posts.append(body)
            self.server.image = body['Image']
            self.server.inserted = True
            if 'external.invalid' in body['Image']:
                self.reply(204)
                return
            try:
                request = urllib.request.Request(self.server.image, headers={'Range': f'bytes={PREFIX}-{PREFIX + LENGTH - 1}'})
                with urllib.request.urlopen(request, timeout=5) as response:
                    self.server.fetched = response.read()
                    self.server.status = response.status
                wrong = self.server.image[:-1] + ('0' if self.server.image[-1] != '0' else '1')
                try:
                    urllib.request.urlopen(wrong, timeout=5)
                    self.server.bad_token_status = 200
                except urllib.error.HTTPError as error:
                    self.server.bad_token_status = error.code
                    error.close()
                self.reply(204)
            except OSError as error:
                self.server.fetch_error = str(error)
                self.reply(500, {})
            return
        if self.path == MEDIA_URI + '/Actions/EjectMedia':
            self.server.ejects += 1
            self.server.inserted = False
            self.reply(204)
            return
        self.reply(404, {})


class MediaMap(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bcontrol-media-map-')
        self.root = Path(self.temp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(self.root / 'key'),
                        '-out', str(self.root / 'cert'), '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.server.inserted, self.server.image, self.server.posts = False, '', []
        self.server.fetched, self.server.status, self.server.bad_token_status = b'', 0, 0
        self.server.ejects, self.server.fetch_error = 0, ''
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / 'cert', self.root / 'key')
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.media_port = sock.getsockname()[1]
        self.image_file = self.root / 'image.iso'
        self.image_file.write_bytes(bytes(range(256)) * 4096)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def test_direct_image_url(self):
        environment = dict(os.environ, BC_BMC_USERNAME=USER, BC_BMC_PASSWORD=PASSWORD)
        command = [AGENT, 'media-map', '--endpoint', 'https://localhost:' + str(self.server.server_port),
                   '--ca', str(self.root / 'cert'), '--auth', 'basic', '--media-uri', MEDIA_URI,
                   '--image-url', 'http://external.invalid/image.iso',
                   '--transfer-method', 'Stream', '--transfer-protocol', 'HTTP']
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        row = json.loads(result.stdout)
        self.assertEqual((row['status'], row['url']), ('ok', 'http://external.invalid/image.iso'))
        self.assertEqual(self.server.posts[0], {'Image': row['url'], 'Inserted': True,
                                                'TransferMethod': 'Stream', 'TransferProtocolType': 'HTTP'})
        self.assertTrue(self.server.inserted)
        self.assertEqual(self.server.ejects, 0)

    def test_serves_ranges_inserts_and_ejects(self):
        environment = dict(os.environ, BC_BMC_USERNAME=USER, BC_BMC_PASSWORD=PASSWORD)
        command = [AGENT, 'media-map', '--endpoint', 'https://localhost:' + str(self.server.server_port),
                   '--ca', str(self.root / 'cert'), '--auth', 'basic', '--media-uri', MEDIA_URI,
                   '--file', str(self.image_file), '--listen', '127.0.0.1:' + str(self.media_port),
                   '--advertise', 'http://127.0.0.1:' + str(self.media_port), '--serve-ms', '500']
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        row = json.loads(result.stdout)
        self.assertEqual(row['status'], 'ok')
        self.assertEqual(row['file_size'], self.image_file.stat().st_size)
        self.assertTrue(row['url'].startswith('http://127.0.0.1:' + str(self.media_port) + '/media/'))
        self.assertEqual(row['eject'], 'ok')
        self.assertEqual(self.server.status, 206)
        data = self.image_file.read_bytes()
        self.assertEqual(self.server.fetched, data[PREFIX:PREFIX + LENGTH])
        self.assertEqual(self.server.bad_token_status, 404)
        self.assertEqual(self.server.ejects, 1)
        self.assertEqual(self.server.posts[0], {'Image': row['url'], 'Inserted': True})
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
