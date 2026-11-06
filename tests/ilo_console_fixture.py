"""Run Apple or desktop iLO console integration against a local TLS/SOCKS5 peer."""
import base64
import hashlib
import http.server
import json
import os
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import traceback
from apple_socks5 import exact, ws_send, ws_receive

TOKEN = '0123456789abcdef0123456789abcdef'
SESSIONS = '/redfish/v1/SessionService/Sessions'
OWN = SESSIONS + '/owned'


class Device(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body=None, headers=()):
        data = b'' if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Type', 'application/json')
        self.send_header('Connection', 'close')
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_GET(self):
        try:
            if self.path == '/redfish/v1/':
                self.reply(200, {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot',
                    'RedfishVersion': '1.17.0',
                    'Managers': {'@odata.id': '/redfish/v1/Managers/'},
                    'Links': {'Sessions': {'@odata.id': SESSIONS}},
                    'Oem': {'Hpe': {'Manager': [{'ManagerType': 'iLO 5'}]}}})
            elif self.path == '/redfish/v1/Managers/':
                assert self.headers['X-Auth-Token'] == TOKEN
                self.reply(200, {'@odata.type': '#ManagerCollection.ManagerCollection',
                    'Members': [{'@odata.id': '/redfish/v1/Managers/1/'}], 'Members@odata.count': 1})
            elif self.path == '/redfish/v1/Managers/1/':
                assert self.headers['X-Auth-Token'] == TOKEN
                self.reply(200, {'@odata.type': '#Manager.v1_0_0.Manager', '@odata.id': self.path,
                    'Id': '1', 'Name': 'iLO 5', 'ManagerType': 'BMC', 'FirmwareVersion': '3.01'})
            elif self.path == '/wss/ircport':
                assert self.headers['Cookie'] == 'sessionKey=' + TOKEN
                assert self.server.active
                accept = base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key'] +
                    '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                self.send_response(101)
                for name, value in [('Upgrade', 'websocket'), ('Connection', 'Upgrade'), ('Sec-WebSocket-Accept', accept)]:
                    self.send_header(name, value)
                self.end_headers()
                self.close_connection = True
                self.connection.settimeout(10)
                hello = ws_receive(self.connection)
                assert len(hello) == 54 and hello[22:] == TOKEN.encode() and hello[17] in (0, 1)
                channel = hello[17]
                with self.server.lock:
                    assert channel not in self.server.channels
                    self.server.channels.append(channel)
                    if len(self.server.channels) == 2:
                        self.server.ready.set()
                ws_send(self.connection, bytes(53))
                if channel == 0:
                    assert self.server.ready.wait(5)
                    # A synthetic 16x16 grey tile, split across WebSocket messages.
                    ws_send(self.connection, bytes([0x0d]))
                    ws_send(self.connection, bytes([0x10, 0x08, 0xf0, 0xff, 0xbf, 0x05]))
                try:
                    while True:
                        packet = ws_receive(self.connection)
                        with self.server.lock:
                            self.server.inputs.append((channel, packet))
                except EOFError:
                    with self.server.lock:
                        self.server.closed.append(channel)
                        if len(self.server.closed) == 2:
                            self.server.both_closed.set()
            else:
                self.reply(404)
        except Exception as error:
            self.server.errors.append(traceback.format_exc())
            self.close_connection = True

    def do_POST(self):
        try:
            assert self.path == SESSIONS
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert body == {'UserName': 'user', 'Password': 'secret'}
            assert not self.server.active
            self.server.active = True
            self.server.logins += 1
            self.reply(201, {'@odata.type': '#Session.v1_8_0.Session', '@odata.id': OWN,
                'Id': 'owned', 'Name': 'User Session', 'UserName': 'user'},
                [('X-Auth-Token', TOKEN), ('Location', 'https://bmc.invalid' + OWN)])
        except Exception as error:
            self.server.errors.append(traceback.format_exc())
            self.reply(400)

    def do_DELETE(self):
        try:
            assert self.path == OWN and self.headers['X-Auth-Token'] == TOKEN
            self.server.active = False
            self.server.logouts += 1
            self.reply(200)
        except Exception as error:
            self.server.errors.append(traceback.format_exc())
            self.reply(400)


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            version, count = exact(self.request, 2)
            assert version == 5 and 2 in exact(self.request, count)
            self.request.sendall(b'\x05\x02')
            assert exact(self.request, 2) == b'\x01\x0a'
            assert exact(self.request, 10) == b'proxy-user'
            assert exact(self.request, 1) == b'\x0c'
            assert exact(self.request, 12) == b'proxy-secret'
            self.request.sendall(b'\x01\x00')
            assert exact(self.request, 5) == b'\x05\x01\x00\x03\x0b'
            assert exact(self.request, 13) == b'bmc.invalid\x01\xbb'
            self.server.connections += 1
            with socket.create_connection(('127.0.0.1', self.server.device.server_port), timeout=5) as remote:
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                while True:
                    ready, _, _ = select.select([self.request, remote], [], [], 10)
                    if not ready:
                        raise TimeoutError('idle proxy tunnel')
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (remote if source is self.request else self.request).sendall(data)
        except Exception as error:
            self.server.device.errors.append(traceback.format_exc())


def main():
    with tempfile.TemporaryDirectory() as directory:
        cert, key = directory + '/cert', directory + '/key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=bmc.invalid', '-keyout', key, '-out', cert],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Device) as device, socketserver.ThreadingTCPServer(('127.0.0.1', 0), Proxy) as proxy:
            proxy.daemon_threads = True
            device.socket = tls.wrap_socket(device.socket, server_side=True)
            device.active = False
            device.logins = device.logouts = 0
            device.errors, device.channels, device.closed, device.inputs = [], [], [], []
            device.ready, device.both_closed, device.lock = threading.Event(), threading.Event(), threading.Lock()
            proxy.device, proxy.connections = device, 0
            workers = [threading.Thread(target=server.serve_forever, daemon=True) for server in (device, proxy)]
            for worker in workers:
                worker.start()
            try:
                env = dict(os.environ, BC_TEST_ILO_PROXY_PORT=str(proxy.server_address[1]))
                result = subprocess.run(sys.argv[1:], env=env, timeout=120)
                device.both_closed.wait(2)
            finally:
                proxy.shutdown(); device.shutdown()
                for worker in workers:
                    worker.join(2)
            assert not device.errors, [str(error) for error in device.errors]
            assert result.returncode == 0, result.returncode
            expected_sessions = 2 if os.environ.get('BC_TEST_ILO_FACTORY') == '1' else 1
            assert device.logins == device.logouts == expected_sessions and not device.active
            assert sorted(device.channels) == sorted(device.closed) == [0, 1]
            packets = [packet for channel, packet in device.inputs if channel == 0]
            assert bytes([1, 0, 2, 0, 4, 0, 0, 0, 0, 0]) in packets, packets
            assert bytes([1, 0]) + bytes(8) in packets
            assert any(len(packet) == 10 and packet[:6] == bytes([2, 0, 0xdc, 5, 0xee, 2]) and packet[8] == 1 for packet in packets)
            assert any(len(packet) == 10 and packet[:6] == bytes([2, 0, 0xdc, 5, 0xee, 2]) and packet[8] == 0 for packet in packets)
            print('Verified iLO dual-channel frame/input/logout via', proxy.connections, 'authenticated proxy connections')


if __name__ == '__main__':
    main()
