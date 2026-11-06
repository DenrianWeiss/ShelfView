"""Verify host timeout overrides against a local delayed Redfish endpoint."""
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time

SESSIONS = '/redfish/v1/SessionService/Sessions'
SYSTEMS = '/redfish/v1/Systems'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body=None, headers=()):
        data = b'' if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Type', 'application/json')
        self.send_header('Connection', 'close')
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # The default timeout intentionally closes the delayed request.

    def do_GET(self):
        if self.path == '/redfish/v1/':
            self.reply(200, {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot',
                'RedfishVersion': '1.17.0', 'Links': {'Sessions': {'@odata.id': SESSIONS}},
                'Systems': {'@odata.id': SYSTEMS}})
        elif self.headers.get('X-Auth-Token') != 'timeout-fixture':
            self.reply(401)
        elif self.path == SYSTEMS:
            self.reply(200, {'@odata.type': '#ComputerSystemCollection.ComputerSystemCollection',
                'Members': [{'@odata.id': SYSTEMS + '/1'}]})
        elif self.path == SYSTEMS + '/1':
            time.sleep(5.3)
            self.reply(200, {'@odata.type': '#ComputerSystem.v1_17_0.ComputerSystem',
                '@odata.id': self.path, 'Id': '1', 'Name': 'Delayed host', 'PowerState': 'On'})
        else:
            self.reply(404)

    def do_POST(self):
        assert self.path == SESSIONS
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert body == {'UserName': 'user', 'Password': 'secret'}
        self.server.logins += 1
        self.reply(201, {'@odata.type': '#Session.v1_0_0.Session', '@odata.id': SESSIONS + '/owned',
            'Id': 'owned', 'Name': 'Test session', 'UserName': 'user'},
            [('X-Auth-Token', 'timeout-fixture'), ('Location', SESSIONS + '/owned')])

    def do_DELETE(self):
        assert self.path == SESSIONS + '/owned'
        assert self.headers.get('X-Auth-Token') == 'timeout-fixture'
        self.server.logouts += 1
        self.reply(200)


def main():
    with tempfile.TemporaryDirectory() as directory:
        cert, key = directory + '/cert', directory + '/key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-keyout', key, '-out', cert], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            server.logins = server.logouts = 0
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                result = subprocess.run(sys.argv[1:], env=dict(os.environ,
                    BC_TEST_HOST_TIMEOUT_URL=f'https://127.0.0.1:{server.server_port}'), timeout=180)
            finally:
                server.shutdown()
                worker.join()
            assert result.returncode == 0, result.returncode
            assert server.logins == server.logouts == 2, (server.logins, server.logouts)
            print('Verified default timeout, extended host timeout, and both session cleanups')


if __name__ == '__main__':
    main()
