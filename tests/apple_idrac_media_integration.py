"""Exercise Apple console-ticket/media separation against localhost only."""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import struct
import subprocess
import tempfile
import threading

KEY = b'123456789012345678901234'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, code, body=b'', headers=()):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path != '/sysmgmt/2015/bmc/session':
            self.reply(404)
            return
        self.server.logins += 1
        self.reply(201, {'authResult': 0}, [('XSRF-TOKEN', 'fixture'), ('Set-Cookie', 'session=fixture; Path=/')])

    def do_DELETE(self):
        self.server.logouts += 1
        self.reply(204)

    def send_message(self, payload):
        length = len(payload)
        self.wfile.write(b'\x82' + (bytes([length]) if length < 126 else b'\x7e' + struct.pack('!H', length)) + payload)
        self.wfile.flush()

    def exact(self, size):
        data = self.rfile.read(size)
        if len(data) != size:
            raise EOFError('incomplete frame')
        return data

    def receive(self):
        first, second = self.exact(2)
        size = second & 127
        if size == 126:
            size = struct.unpack('!H', self.exact(2))[0]
        elif size == 127:
            size = struct.unpack('!Q', self.exact(8))[0]
        if size > 8192 or not second & 128:
            raise ValueError('invalid fixture frame')
        mask = self.exact(4)
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(self.exact(size)))
        if first & 15 == 8:
            raise EOFError('closed')
        if first != 0x82:
            raise ValueError('expected complete binary message')
        return payload

    def do_GET(self):
        if self.path == '/sysmgmt/2015/server/vconsole?type=eHTML5':
            port = self.server.server_port
            self.reply(200, {'Location': f'https://localhost:{port}/restgui/vconsole/index.html?ip=localhost&kvmport={port}&VCSID=fixture-ticket&VCSID2=fixture-secondary'})
            return
        if self.path not in ('/vnc/vconsole?vck=fixture-ticket', '/vnc/vmedia?vmk=fixture-ticket'):
            self.reply(404)
            return
        self.close_connection = True
        self.connection.settimeout(15)
        accept = base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.send_response(101)
        for key, value in [('Upgrade', 'websocket'), ('Connection', 'Upgrade'),
                           ('Sec-WebSocket-Accept', accept), ('Sec-WebSocket-Protocol', 'binary')]:
            self.send_header(key, value)
        self.end_headers()
        try:
            if '/vconsole?' in self.path:
                self.server.consoles += 1
                self.send_message(bytes([247, 179]))
                assert self.receive() == bytes([247, 179]) + b'fixture-secondary' + bytes(8)
                if self.server.mode in ('denied', 'busy'):
                    self.send_message(bytes([247, 169, 8]) if self.server.mode == 'denied' else bytes([247, 164]))
                else:
                    self.send_message(b'RFB 003.008\n')
                    listing = bytes([247, 172, 0, 0, 0, 0]) + KEY + bytes(335)
                    self.send_message(listing[:10] if self.server.mode == 'truncated' else listing)
                assert self.receive() == bytes([247, 0, 249]), 'no RFB, input or extra authentication is allowed'
                self.server.console_closes += 1
            else:
                self.server.media += 1
                self.send_message(struct.pack('<4I', 8192, 0, 0, 7))
                assert self.receive() == struct.pack('<4I', 8192, 0, 32, 7) + KEY + bytes(8)
                self.send_message(struct.pack('<4I', 16, 0, 24, 7) + KEY)
                assert len(self.receive()) == 44
                assert len(self.receive()) == 36
                assert self.receive() == bytes([0x5a]) * 4096
                self.send_message(struct.pack('<5I', 256, 1, 4, 7, 70))
                assert self.receive() == struct.pack('<4I', 8, 1, 0, 7)
                self.send_message(struct.pack('<5I', 256, 1, 4, 7, 25))
                assert self.receive() == struct.pack('<4I', 1024, 0, 0, 7)
        except Exception as error:
            self.server.errors.append(str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-build', type=Path, required=True)
    parser.add_argument('--swift-scratch', type=Path, default=Path('build-apple'))
    parser.add_argument('--desktop-dotnet', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    c_build = args.c_build.resolve()
    with tempfile.TemporaryDirectory(prefix='apple-idrac-media-') as directory:
        directory = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(directory / 'key'),
                        '-out', str(directory / 'cert'), '-days', '1', '-subj', '/CN=localhost'], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / 'cert', directory / 'key')
        for mode in ('complete', 'denied', 'busy', 'truncated'):
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            server.mode, server.errors = mode, []
            server.logins = server.logouts = server.consoles = server.console_closes = server.media = 0
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            try:
                environment = {key: value for key, value in os.environ.items() if not key.startswith(('BC_TEST_', 'BC_LIVE_', 'BC_BMC_'))}
                environment.update(BC_TEST_IDRAC_MEDIA_FIXTURE=f'https://localhost:{server.server_port}', BC_TEST_IDRAC_MEDIA_MODE=mode)
                command = ([str(args.desktop_dotnet.resolve()), 'test', str(root / 'frontends/desktop/tests/BControl.Core.Tests'),
                    '--no-restore', '-m:1', '-p:BControlNativeDir=' + str(c_build), '-v:q',
                    '--filter', 'ConsoleTicketAndMediaUseSeparateChannels'] if args.desktop_dotnet else
                    ['swift', 'test', '--package-path', str(root / 'frontends/apple'),
                    '--scratch-path', str(args.swift_scratch.resolve()), '-Xcc', '-I', '-Xcc', str(root / 'include'),
                    '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'), '-Xlinker', '-L', '-Xlinker', str(c_build),
                    '-Xlinker', '-rpath', '-Xlinker', str(c_build), '--filter', 'testLocalMediaConsoleAuthenticationFixture'])
                subprocess.run(command, env=environment, cwd=root, check=True, timeout=120)
                if server.errors or (server.logins, server.logouts, server.consoles, server.console_closes, server.media) != (1, 1, 1, 1, int(mode == 'complete')):
                    raise RuntimeError(f'Fixture {mode}: errors={server.errors}, counts={(server.logins, server.logouts, server.consoles, server.console_closes, server.media)}')
                print(('Desktop' if args.desktop_dotnet else 'Apple') + ' iDRAC media fixture passed: ' + mode, flush=True)
            finally:
                server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    main()
