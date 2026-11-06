import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import ssl
import sys
import zlib
import tempfile
import threading
import time
import unittest

AGENT = str(Path(sys.argv.pop(1)).resolve()) if __name__ == '__main__' else None
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def rfb_stream():
    init = bytearray(24)
    init[1], init[3] = 2, 2
    init[4], init[5], init[7] = 32, 24, 1
    init[9] = init[11] = init[13] = 255
    init[14], init[15], init[16] = 16, 8, 0
    init[23] = 2
    update = bytes([0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0])
    pixels = bytes([0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0])
    return b'RFB 003.008\n' + bytes([1, 1]) + b'\x00\x00\x00\x00' + bytes(init) + b'ws' + update + pixels


def ws_frame(opcode, payload, rsv1=False):
    header = bytes([0x80 | (0x40 if rsv1 else 0) | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length <= 65535:
        header += bytes([126]) + length.to_bytes(2, 'big')
    else:
        header += bytes([127]) + length.to_bytes(8, 'big')
    return header + payload


class Server(threading.Thread):
    def __init__(self, context=None, deflate=False, fragmented=False):
        super().__init__(daemon=True)
        self.context = context
        self.deflate = deflate
        self.fragmented = fragmented
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.error = ''

    def run(self):
        try:
            connection, _ = self.socket.accept()
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
            with connection:
                request = b''
                while b'\r\n\r\n' not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        return
                    request += chunk
                headers = {}
                for line in request.split(b'\r\n')[1:]:
                    if b':' in line:
                        key, value = line.split(b':', 1)
                        headers[key.strip().lower()] = value.strip()
                accept = base64.b64encode(hashlib.sha1(headers[b'sec-websocket-key'] + GUID.encode()).digest()).decode()
                extensions = ''
                if self.deflate:
                    extensions = ('Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; '
                                  'client_no_context_takeover\r\n')
                connection.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                                    'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n' +
                                    extensions + '\r\n').encode())
                connection.sendall(ws_frame(0x9, b'ping'))
                stream = b'RFB 003.008\n' + bytes([1, 1]) + b'\x00\x00\x00\x00' 
                stream = rfb_stream()
                split = 12 + 2 + 4 + 24 + 2
                if self.deflate:
                    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
                    compressed = compressor.compress(stream) + compressor.flush(zlib.Z_SYNC_FLUSH)
                    if self.fragmented:
                        split = len(compressed) // 2
                        first = bytearray(ws_frame(0x2, compressed[:split], rsv1=True))
                        first[0] &= 0x7f
                        connection.sendall(first + ws_frame(0, compressed[split:]))
                    else:
                        connection.sendall(ws_frame(0x2, compressed, rsv1=True))
                else:
                    connection.sendall(ws_frame(0x2, stream[:split]))
                    connection.sendall(ws_frame(0x2, stream[split:]))
                while connection.recv(4096):
                    pass
        except OSError as error:
            self.error = str(error)
        finally:
            self.socket.close()


class RawServer(threading.Thread):
    def __init__(self, context=None):
        super().__init__(daemon=True)
        self.context = context
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.error = ''
        self.received = bytearray()

    def run(self):
        try:
            connection, _ = self.socket.accept()
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
            with connection:
                connection.sendall(rfb_stream())
                while True:
                    data = connection.recv(4096)
                    if not data:
                        break
                    self.received.extend(data)
        except OSError as error:
            self.error = str(error)
        finally:
            self.socket.close()


class KVMRaw(unittest.TestCase):
    def run_client(self, secure):
        with tempfile.TemporaryDirectory(prefix='bcontrol-kvm-') as directory:
            root = Path(directory)
            context = None
            scheme, args = 'tcp', []
            if secure:
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key'),
                                '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=localhost',
                                '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / 'cert', root / 'key')
                scheme, args = 'tls', ['--ca', str(root / 'cert')]
            server = RawServer(context)
            server.start()
            output = root / 'frame.ppm'
            result = subprocess.run([AGENT, 'kvm', '--url', scheme + '://localhost:' + str(server.port),
                                     '--seconds', '5', '--out', str(output)] + args,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout + server.error)
            row = json.loads(result.stdout)
            self.assertEqual((row['status'], row['transport'], row['width'], row['height']), ('ok', 2 if secure else 1, 2, 2))
            self.assertEqual(output.read_bytes()[11:], bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]))
            server.join(timeout=5)

    def test_raw_tcp_rfb_frame(self):
        self.run_client(False)

    def test_raw_tls_rfb_frame(self):
        self.run_client(True)


class KVMWebSocket(unittest.TestCase):
    def test_slow_upgrade_headers_share_connection_deadline(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    connection.recv(4096)
                    for byte in b'HTTP/1.1 101 Switching Protocols\r\n':
                        if stop.wait(0.05):
                            break
                        connection.sendall(bytes([byte]))
            except OSError:
                pass

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            started = time.monotonic()
            result = subprocess.run([AGENT, 'kvm', '--url', f'ws://127.0.0.1:{port}',
                                     '--timeout-ms', '300'], capture_output=True, text=True, timeout=4)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['status'], 'timeout')
            self.assertLess(time.monotonic() - started, 1.5)
        finally:
            stop.set()
            listener.close()
            worker.join(timeout=3)

    def run_client(self, secure, deflate=False, fragmented=False):
        with tempfile.TemporaryDirectory(prefix='bcontrol-kvm-') as directory:
            root = Path(directory)
            context = None
            args = []
            scheme = 'ws'
            if secure:
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key'),
                                '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=localhost',
                                '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / 'cert', root / 'key')
                args = ['--ca', str(root / 'cert')]
                scheme = 'wss'
            server = Server(context, deflate, fragmented)
            server.start()
            output = root / 'frame.ppm'
            extra = ['--deflate'] if deflate else []
            result = subprocess.run([AGENT, 'kvm', '--url', scheme + '://localhost:' + str(server.port) + '/kvm',
                                     '--seconds', '5', '--out', str(output)] + args + extra,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout + server.error)
            row = json.loads(result.stdout)
            self.assertEqual((row['status'], row['transport'], row['width'], row['height']), ('ok', 4 if secure else 3, 2, 2))
            data = output.read_bytes()
            self.assertEqual(data[:11], b'P6\n2 2\n255\n')
            self.assertEqual(data[11:], bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]))
            server.join(timeout=5)

    def test_websocket_rfb_frame(self):
        self.run_client(False)

    def test_secure_websocket_rfb_frame(self):
        self.run_client(True)

    def test_compressed_websocket_rfb_frame(self):
        self.run_client(False, True)

    def test_fragmented_compressed_websocket_rfb_frame(self):
        self.run_client(True, True, True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
