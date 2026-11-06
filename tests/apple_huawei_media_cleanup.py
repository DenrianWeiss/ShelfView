"""Exercise Huawei VMM cleanup against a local synthetic WebSocket peer."""
import argparse
import base64
import hashlib
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from apple_idrac_media_integration import Handler as WebSocketHandler


class Handler(WebSocketHandler):
    def do_GET(self):
        if self.path != '/websocket':
            self.reply(404)
            return
        self.close_connection = True
        self.connection.settimeout(10)
        accept = base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.send_response(101)
        for key, value in [('Upgrade', 'websocket'), ('Connection', 'Upgrade'), ('Sec-WebSocket-Accept', accept)]:
            self.send_header(key, value)
        self.end_headers()
        try:
            assert self.receive()[0] == 1
            self.send_message(bytes(12))
            create = self.receive()
            assert create[:2] == bytes([2, 2])
            self.server.creates += 1
            ack = bytearray(12)
            ack[2] = 0x11 if self.server.mode == 'create-error' else 0x10
            self.send_message(ack)
            if self.server.mode == 'remote':
                close = bytearray(12); close[0] = 5; close[1] = 2
                self.send_message(close)
                try:
                    self.receive()
                    raise ValueError('unexpected request after peer closure')
                except EOFError:
                    pass
            elif self.server.mode == 'disconnect':
                self.wfile.write(b'\x88\x00'); self.wfile.flush()
            else:
                assert self.receive()[:2] == bytes([5, 2])
                self.server.closes += 1
        except Exception as error:
            self.server.errors.append(str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-build', type=Path, required=True)
    parser.add_argument('--swift-scratch', type=Path, default=Path('build-apple'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    c_build = args.c_build.resolve()
    with tempfile.TemporaryDirectory(prefix='apple-huawei-cleanup-') as directory:
        directory = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(directory / 'key'),
                        '-out', str(directory / 'cert'), '-days', '1', '-subj', '/CN=localhost'], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / 'cert', directory / 'key')
        for mode in ('local', 'remote', 'disconnect', 'create-error'):
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            server.mode, server.errors, server.creates, server.closes = mode, [], 0, 0
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            try:
                environment = {key: value for key, value in os.environ.items() if not key.startswith(('BC_TEST_', 'BC_LIVE_', 'BC_BMC_'))}
                environment.update(BC_TEST_HUAWEI_MEDIA_FIXTURE_PORT=str(server.server_port), BC_TEST_HUAWEI_MEDIA_FIXTURE_MODE=mode)
                subprocess.run(['swift', 'test', '--package-path', str(root / 'frontends/apple'),
                    '--scratch-path', str(args.swift_scratch.resolve()), '-Xcc', '-I', '-Xcc', str(root / 'include'),
                    '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'), '-Xlinker', '-L', '-Xlinker', str(c_build),
                    '-Xlinker', '-rpath', '-Xlinker', str(c_build), '--filter', 'testLocalMediaCleanupFixture'],
                    env=environment, cwd=root, check=True, timeout=120)
                if server.errors or server.creates != 1 or server.closes != int(mode in ('local', 'create-error')):
                    raise RuntimeError(f'{mode}: {server.errors}, creates={server.creates}, closes={server.closes}')
                print('Apple Huawei cleanup fixture passed: ' + mode, flush=True)
            finally:
                server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    main()
