import base64
import hashlib
import json
import http.server
import ssl
import time
import urllib.parse
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import zlib

AGENT = str(Path(sys.argv.pop(1)).resolve())
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
FRAME_SIZE = 640
FRAME_DATA = b'ABCDEF'


def ws_frame(opcode, payload, final=True):
    length = len(payload)
    first = (0x80 if final else 0) | opcode
    if length < 126:
        header = bytes([first, length])
    elif length < 65536:
        header = bytes([first, 126]) + length.to_bytes(2, 'big')
    else:
        header = bytes([first, 127]) + length.to_bytes(8, 'big')
    return header + payload


def recv_frame(connection, text=False):
    head = connection.recv(2)
    if len(head) < 2:
        return None
    length = head[1] & 0x7f
    if length == 126:
        length = int.from_bytes(connection.recv(2), 'big')
    mask = connection.recv(4)
    payload = b''
    while len(payload) < length:
        payload += connection.recv(length - len(payload))
    data = bytes(payload[i] ^ mask[i % 4] for i in range(length))
    if text:
        assert head[0] == 0x81
        return base64.b64decode(data, validate=True)
    return data


class ProbeServer(threading.Thread):
    def __init__(self, certificate, zte=False):
        super().__init__(daemon=True)
        self.zte = zte
        self.certificate = certificate
        self.server = None
        self.error = ''
        self.paths = []

    def run(self):
        zte = self.zte
        paths = self.paths
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

            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                form = urllib.parse.parse_qs(self.rfile.read(length).decode())
                if self.path == '/api/session' and ((not zte and form.get('username') == ['admin'] and form.get('password') == ['probe-password']) or (zte and form == {'cmccflag': ['true'], 'cmcctoken': ['launch-token'], 'kvmflag': ['true']})):
                    self.reply(200, {'ok': True, 'CSRFToken': 'csrf-token'},
                               [('Set-Cookie', 'QSESSIONID=probe-session; Path=/; HttpOnly')])
                else:
                    self.reply(401, {'ok': False})

            def do_DELETE(self):
                paths.append(('DELETE', self.path))
                length = int(self.headers.get('Content-Length', '0')); self.rfile.read(length)
                self.reply(204, {})

            def do_GET(self):
                paths.append(('GET', self.path))
                if zte and self.path == '/redfish/v1/':
                    old = zte in ('g4', 'g4-java')
                    root = {'RedfishVersion': '1.8.1' if old else '1.15.1',
                            'Managers': {'@odata.id': '/redfish/v1/Managers'}}
                    if not old: root['Product'] = 'ZTE Redfish Server'
                    self.reply(200, root); return
                if zte and self.path.startswith('/redfish/v1/Managers'):
                    if self.headers.get('Authorization') != 'Basic ' + base64.b64encode(b'admin:probe-password').decode():
                        self.reply(401, {}); return
                    if self.path == '/redfish/v1/Managers':
                        self.reply(200, {'Members': [{'@odata.id': '/redfish/v1/Managers/Self'}]}); return
                    if self.path == '/redfish/v1/Managers/Self':
                        self.reply(200, {'@odata.id': self.path, 'KvmService': {'@odata.id': self.path + '/KvmService'},
                            'Actions': {'Oem': {'#Manager.Dump': {'target': self.path + '/Actions/Oem/ZTE/Manager.Dump'}}}}); return
                    if self.path == '/redfish/v1/Managers/Self/KvmService':
                        self.reply(200, {'@odata.id': self.path, '@odata.type': '#KvmService.v1_0_0.KvmService',
                            'KvmUrl': 'https://localhost:' + str(self.server.server_port) + '/viewer.html?&token=launch-token'}); return
                if self.path == '/index.html':
                    self.reply(404, {}); return
                if self.path == '/api/settings/media/remote/h5kvm_enable_flag' and zte:
                    if zte not in ('g4', 'g4-java'):
                        self.reply(404, {}); return
                    if self.headers.get('X-CSRFTOKEN') == 'csrf-token' and 'QSESSIONID=probe-session' in self.headers.get('Cookie', ''):
                        self.reply(200, {'h5kvm_enableflag': int(zte != 'g4-java')}); return
                if zte == 'g4-java' and self.path == '/Java/jviewer.jnlp?EXTRNIP=localhost&JNLPSTR=JViewer':
                    self.reply(403, {}); return
                if self.path == '/viewer.min.js' and zte == 'g4':
                    raw = b"""let layout = {VIDEO_PACKET_SIZE: 373, SSI_HASH_SIZE: 129, CLIENT_USERNAME_LENGTH: 129,
                        CLINET_OWN_IP_LENGTH: 65, CLINET_OWN_MAC_LENGTH: 49};
                        let config = '/api/settings/media/h5viewercfg', kvm = '/kvm', cd = '/cd-server';"""
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path == '/api/settings/media/h5viewercfg' and \
                        'QSESSIONID=probe-session' in self.headers.get('Cookie', '') and \
                        self.headers.get('X-CSRFTOKEN') == 'csrf-token':
                    self.reply(200, {'token': 'kvm-token', 'session': 's', 'client_ip': '192.0.2.10',
                                     'server_ip': '192.0.2.1'})
                else:
                    self.reply(401, {})

        try:
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certificate[0], self.certificate[1])
            server.socket = context.wrap_socket(server.socket, server_side=True)
            self.server = server
            self.port = server.server_port
            server.serve_forever(poll_interval=.01)
        except OSError as error:
            self.error = str(error)


class Server(threading.Thread):
    def __init__(self, kind, protocol='binary', deflate=False):
        super().__init__(daemon=True)
        self.kind = kind
        self.protocol = protocol
        self.deflate = deflate
        self.cookie = ''
        self.token = ''
        self.custom_payload = None
        self.custom_width = FRAME_SIZE
        self.custom_height = 480
        self.input_packets = []
        self.coalesced = False
        self.frame_count = 1
        self.soc_frames = None
        self.coalesced_frames = False
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.auth_length = 0
        self.error = ''

    def run(self):
        try:
            connection, _ = self.socket.accept()
            with connection:
                request = b''
                while b'\r\n\r\n' not in request:
                    request += connection.recv(4096)
                headers = {}
                for line in request.split(b'\r\n')[1:]:
                    if b':' in line:
                        key, value = line.split(b':', 1)
                        headers[key.strip().lower()] = value.strip()
                self.cookie = headers.get(b'cookie', b'').decode(errors='replace')
                accept = base64.b64encode(hashlib.sha1(headers[b'sec-websocket-key'] + GUID.encode()).digest()).decode()
                text = self.protocol != 'binary'
                if text:
                    assert b'base64' in headers[b'sec-websocket-protocol']
                protocol = '' if self.protocol is None else 'Sec-WebSocket-Protocol: ' + self.protocol + '\r\n'
                extensions = ('Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; '
                              'client_no_context_takeover\r\n') if self.deflate else ''
                connection.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                                    'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept +
                                    '\r\n' + protocol + extensions + '\r\n').encode())

                def send(data, fragmented=False):
                    if not text:
                        connection.sendall(ws_frame(2, data))
                        return
                    encoded = base64.b64encode(data)
                    opcode = 1
                    if self.deflate:
                        compressor = zlib.compressobj(wbits=-15)
                        encoded = (compressor.compress(encoded) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
                        opcode |= 0x40
                    if fragmented:
                        connection.sendall(ws_frame(opcode, encoded[:5], final=False) + ws_frame(0, encoded[5:]))
                    else:
                        connection.sendall(ws_frame(opcode, encoded))

                send(struct.pack("<HIH", 23, 0, 2), fragmented=True)
                frame = recv_frame(connection, text)
                offset = 0
                while frame and offset + 8 <= len(frame):
                    kind, length, _ = struct.unpack_from('<HIH', frame, offset)
                    if kind == 18:
                        self.auth_length = length
                        token = frame[offset + 9:offset + 9 + 129].split(b'\x00', 1)[0]
                        self.token = token.decode(errors='replace')
                    offset += 8 + length
                valid = struct.pack('<HIH', 19, 1, 0) + b'\x01'
                if not self.coalesced:
                    send(valid)
                payload = self.custom_payload if self.custom_payload is not None else FRAME_DATA
                ast = bytearray(86)
                struct.pack_into('<H', ast, 4, self.custom_width)
                struct.pack_into('<H', ast, 6, self.custom_height)
                struct.pack_into('<H', ast, 13, self.custom_width)
                struct.pack_into('<H', ast, 15, self.custom_height)
                struct.pack_into('<I', ast, 26, 1)
                struct.pack_into('<I', ast, 69, len(payload))
                fragment = b'\x00\x00' + bytes(ast) + payload
                fragments = [b'\x00\x80' + frame for frame in self.soc_frames] if self.soc_frames is not None else [fragment] * self.frame_count
                messages = [struct.pack('<HIH', 25, len(part), 0) + part for part in fragments]
                if self.coalesced_frames:
                    messages = [b''.join(messages)]
                for index, message in enumerate(messages):
                    send((valid if self.coalesced and not index else b'') + message, fragmented=True)
                while True:
                    frame = recv_frame(connection, text)
                    if frame is None:
                        break
                    offset = 0
                    while offset + 8 <= len(frame):
                        kind, length, _ = struct.unpack_from('<HIH', frame, offset)
                        if kind == 1 and length >= 39:
                            payload = frame[offset + 8:offset + 8 + length]
                            self.input_packets.append((payload[17], payload[33:]))
                        offset += 8 + length
        except OSError as error:
            self.error = str(error)
        finally:
            self.socket.close()


class MegaRACKVM(unittest.TestCase):
    def run_kind(self, kind, protocol='binary', deflate=False):
        server = Server(kind, protocol, deflate)
        server.start()
        with tempfile.TemporaryDirectory(prefix='bcontrol-megarac-') as directory:
            output = Path(directory) / 'frame.bin'
            arguments = [AGENT, 'megarac-kvm', '--url', 'ws://127.0.0.1:' + str(server.port) + '/kvm',
                         '--kind', kind, '--token', 'kvm-token', '--client-ip', '192.0.2.10',
                         '--username', 'admin', '--seconds', '5', '--out', str(output)]
            if kind == 'h5':
                arguments += ['--server-ip', '192.0.2.1']
            if deflate:
                arguments += ['--deflate']
            result = subprocess.run(arguments, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout + server.error)
            row = json.loads(result.stdout)
            self.assertEqual((row['status'], row['transport'], row['subprotocol']), ('ok', 3, 1 if protocol == 'binary' else 2))
            self.assertEqual((row['width'], row['height'], row['compressed_size']), (FRAME_SIZE, 480, 6))
            self.assertEqual(output.read_bytes(), FRAME_DATA)
            self.assertEqual(server.auth_length, 438 if kind == 'h5' else 373)
        server.join(timeout=2)

    def test_h5_session_and_frame(self):
        self.run_kind('h5')

    def test_zte_login_and_kvm(self):
        self.test_probe_login_and_kvm(zte=True)

    def test_zte_g4_detects_legacy_h5_without_product_field(self):
        self.test_probe_login_and_kvm(zte='g4')

    def test_zte_g4_disabled_h5_requests_jnlp_and_closes_rest_session(self):
        self.test_probe_login_and_kvm(zte='g4-java')

    def test_probe_login_and_kvm(self, zte=False):
        server = None if zte == 'g4-java' else Server('h5')
        if server: server.start()
        with tempfile.TemporaryDirectory(prefix='bcontrol-megarac-') as directory:
            root = Path(directory)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key'),
                            '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
            probe = ProbeServer((root / 'cert', root / 'key'), zte=zte)
            probe.start()
            try:
                for _ in range(100):
                    if probe.server:
                        break
                    time.sleep(.02)
                output = root / 'frame.bin'
                result = subprocess.run([AGENT, '--log-level', 'verbose' if zte == 'g4' else 'off', 'megarac-kvm',
                                         '--endpoint', 'https://localhost:' + str(probe.port),
                                         '--ca', str(root / 'cert'), '--username', 'admin', '--password', 'probe-password',
                                         '--url', 'ws://127.0.0.1:' + str(server.port if server else 1) + '/kvm',
                                         '--seconds', '5', '--out', str(output)],
                                        capture_output=True, text=True, timeout=20)
                row = json.loads(result.stdout)
                if zte == 'g4-java':
                    self.assertEqual((result.returncode, row['status'], row['logout']), (1, 'authentication_failed', 'ok'))
                    self.assertIn(('GET', '/Java/jviewer.jnlp?EXTRNIP=localhost&JNLPSTR=JViewer'), probe.paths)
                    self.assertNotIn(('GET', '/api/settings/media/h5viewercfg'), probe.paths)
                    self.assertEqual(probe.paths.count(('DELETE', '/api/session')), 1)
                    return
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout + server.error)
                self.assertEqual((row['status'], row['kind'], row['cookie']), ('ok', 4 if zte == 'g4' else 2, True))
                self.assertEqual(server.auth_length, 373 if zte == 'g4' else 438)
                self.assertIn('QSESSIONID=probe-session', server.cookie)
                self.assertEqual(server.token, 'kvm-token')
                self.assertEqual(output.read_bytes(), FRAME_DATA)
            finally:
                if probe.server:
                    probe.server.shutdown()
                    probe.server.server_close()
                probe.join(timeout=2)
        server.join(timeout=2)

    def test_jviewer_session_and_frame(self):
        self.run_kind('jviewer')

    def test_h5_base64_transport(self):
        for protocol, deflate in (('base64', False), (None, False), ('base64', True)):
            with self.subTest(protocol=protocol, deflate=deflate):
                self.run_kind('h5', protocol, deflate)

    def test_keyboard_and_mouse_input(self):
        server = Server('h5')
        server.coalesced = True
        server.start()
        with tempfile.TemporaryDirectory(prefix='bcontrol-megarac-') as directory:
            result = subprocess.run([AGENT, 'megarac-kvm', '--url', 'ws://127.0.0.1:' + str(server.port) + '/kvm',
                                     '--kind', 'h5', '--token', 'kvm-token', '--client-ip', '192.0.2.10',
                                     '--username', 'admin', '--server-ip', '192.0.2.1', '--seconds', '5',
                                     '--key', 'a', '--mouse', '100,200'], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout + server.error)
            self.assertTrue(json.loads(result.stdout)['input'])
            for _ in range(50):
                if len(server.input_packets) >= 3:
                    break
                time.sleep(.02)
            keyboard = [report for device, report in server.input_packets if device == 48]
            mouse = [report for device, report in server.input_packets if device == 49]
            self.assertTrue(any(report[2] == 0x04 for report in keyboard), server.input_packets)
            self.assertEqual(keyboard[-1], bytes(8), server.input_packets)
            self.assertTrue(mouse and struct.unpack('<H', mouse[0][1:3])[0] == 100 and
                            struct.unpack('<H', mouse[0][3:5])[0] == 200, result.stderr + str(server.input_packets))
        server.join(timeout=2)

    def test_multiple_frames(self):
        server = Server('h5')
        server.custom_payload = bytes([0x01, 0x01, 0xd7, 0x59, 0x00, 0x00, 0x00, 0x20])
        server.custom_width, server.custom_height = 1920, 1080
        server.frame_count = 2
        server.start()
        with tempfile.TemporaryDirectory(prefix='bcontrol-megarac-') as directory:
            base = Path(directory) / 'frame.ppm'
            result = subprocess.run([AGENT, 'megarac-kvm', '--url', 'ws://127.0.0.1:' + str(server.port) + '/kvm',
                                     '--kind', 'h5', '--token', 'kvm-token', '--client-ip', '192.0.2.10',
                                     '--username', 'admin', '--server-ip', '192.0.2.1', '--seconds', '5',
                                     '--frames', '2', '--ppm', str(base)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout + server.error)
            self.assertEqual(json.loads(result.stdout)['frames'], 2)
            for index in range(2):
                data = (Path(directory) / f'frame-{index:03}.ppm').read_bytes()
                self.assertTrue(data.startswith(b'P6\n1920 1080\n255\n'))
        server.join(timeout=2)

    def test_soc_text_geometry_and_font_cache(self):
        server = Server('jviewer195')
        frame = bytearray(36 + 65536)
        struct.pack_into('<I', frame, 5, len(frame) - 34)
        struct.pack_into('<HH', frame, 9, 1, 2)
        frame[21:25] = bytes([1, 1, 6, 2])
        frame[29], frame[34], frame[35] = 28, ord('A'), 0x1f
        frame[36 + ord('A') * 32] = 0x80
        following = bytearray(frame[:36])
        struct.pack_into('<I', following, 5, 2)
        following[29] = 12
        server.soc_frames = [frame, following]
        server.coalesced_frames = True
        server.start()
        with tempfile.TemporaryDirectory(prefix='bcontrol-soc-text-') as directory:
            result = subprocess.run([AGENT, 'megarac-kvm', '--url', 'ws://127.0.0.1:' + str(server.port) + '/kvm',
                                     '--kind', 'jviewer195', '--token', 'fixture-token', '--client-ip', '192.0.2.10',
                                     '--username', 'admin', '--seconds', '5', '--frames', '2',
                                     '--ppm', str(Path(directory) / 'text.ppm')], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr + server.error)
            row = json.loads(result.stdout)
            self.assertEqual((row['decoded_width'], row['decoded_height'], row['decode_status']), (8, 2, 'ok'))
            first = (Path(directory) / 'text-000.ppm').read_bytes()
            self.assertTrue(first.startswith(b'P6\n8 2\n255\n\xff\xff\xff\x00\x00\xaa'))
            self.assertEqual(first, (Path(directory) / 'text-001.ppm').read_bytes())
        server.join(timeout=2)

    def test_vq_frame_decodes_to_ppm(self):
        server = Server('h5')
        server.custom_payload = bytes([0x01, 0x01, 0xd7, 0x59, 0x00, 0x00, 0x00, 0x20])
        server.custom_width = server.custom_height = 8
        server.start()
        with tempfile.TemporaryDirectory(prefix='bcontrol-megarac-') as directory:
            output = Path(directory) / 'frame.ppm'
            result = subprocess.run([AGENT, 'megarac-kvm', '--url', 'ws://127.0.0.1:' + str(server.port) + '/kvm',
                                     '--kind', 'h5', '--token', 'kvm-token', '--client-ip', '192.0.2.10',
                                     '--username', 'admin', '--server-ip', '192.0.2.1', '--seconds', '5',
                                     '--ppm', str(output)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout + server.error)
            row = json.loads(result.stdout)
            self.assertEqual((row.get('decode'), row.get('decoded_width'), row.get('decoded_height')), ('ok', 8, 8), row)
            data = output.read_bytes()
            self.assertEqual(data[:11], b'P6\n8 8\n255\n')
            self.assertEqual(data[11:14], bytes([255, 255, 255]))
        server.join(timeout=2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
