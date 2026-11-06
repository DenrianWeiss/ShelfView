"""Independent HTTPS fixture for Apple C-backed discovery and cleanup."""
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import time

root = Path(__file__).resolve().parents[1]
sessions = {}
calls = []
lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def handle(self):
        try:
            super().handle()
        except OSError:
            pass

    def log_message(self, *_):
        pass

    def reply(self, code, value=None, headers=()):
        payload = b'' if value is None else json.dumps(value).encode()
        try:
            self.send_response(code)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Content-Type', 'application/json')
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            self.close_connection = True

    def user(self):
        with lock:
            calls.append((self.command, self.path, self.headers.get('Authorization')))
            return sessions.get(self.headers.get('X-Auth-Token'))

    def do_GET(self):
        user = self.user()
        if self.path == '/redfish/v1/':
            self.reply(200, {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot',
                            'RedfishVersion': '1.17.0', 'Systems': {'@odata.id': '/redfish/v1/Systems'},
                            'Links': {'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}}})
        elif not user:
            self.reply(401)
        elif self.path == '/redfish/v1/Systems':
            self.reply(200, {'@odata.type': '#ComputerSystemCollection.ComputerSystemCollection',
                            'Members': [{'@odata.id': '/redfish/v1/Systems/1'}, {'@odata.id': '/redfish/v1/Systems/2'}]})
        elif self.path in ('/redfish/v1/Systems/1', '/redfish/v1/Systems/2'):
            if user == 'slow':
                time.sleep(.3)
            if user == 'timeout':
                time.sleep(6)
            first = self.path.endswith('/1')
            body = {'@odata.type': '#ComputerSystem.v1_20_0.ComputerSystem', 'Id': self.path[-1],
                    'Name': 'Node ' + self.path[-1], 'Manufacturer': 'Fixture' if first else 'Other',
                    'Model': 'Model', 'HostName': 'host', 'PowerState': 'On' if first else 'Off',
                    'Links': {'Chassis': [{'@odata.id': '/redfish/v1/Chassis/1'}]}}
            if user == 'powering-on': body['PowerState'] = 'PoweringOn'
            elif user == 'powering-off': body['PowerState'] = 'PoweringOff'
            elif user == 'no-power': body.pop('PowerState')
            self.reply(200, body)
        elif self.path == '/redfish/v1/Chassis/1':
            self.reply(200, {'@odata.type': '#Chassis.v1_28_0.Chassis',
                            'Links': {'ComputerSystems': [{'@odata.id': '/redfish/v1/Systems/1'}, {'@odata.id': '/redfish/v1/Systems/2'}]},
                            'Sensors': {'@odata.id': '/redfish/v1/Chassis/1/Sensors'}})
        elif self.path == '/redfish/v1/Chassis/1/Sensors':
            names = ['cpu-hot', 'cpu-normal', 'inlet', 'other-node', 'shared', 'headroom', 'disabled', 'range', 'fan', 'unknown-health']
            if user == 'partial': names.append('broken')
            self.reply(200, {'@odata.type': '#SensorCollection.SensorCollection',
                            'Members': [{'@odata.id': self.path + '/' + name} for name in names]})
        elif self.path.startswith('/redfish/v1/Chassis/1/Sensors/'):
            name = self.path.rsplit('/', 1)[1]
            if name == 'broken':
                self.reply(500)
                return
            if user == 'slow-sensor' and name == 'cpu-hot': time.sleep(6)
            body = {'@odata.type': '#Sensor.v1_11_0.Sensor', 'Name': name, 'ReadingType': 'Temperature',
                    'Reading': 95, 'ReadingUnits': 'Cel', 'PhysicalContext': 'CPU',
                    'RelatedItem': [{'@odata.id': '/redfish/v1/Systems/1/Processors/1'}],
                    'Status': {'State': 'Enabled', 'Health': 'OK'}}
            if name == 'cpu-hot': body['Status']['Health'] = 'Critical'
            elif name == 'cpu-normal': body.update(Reading=158, ReadingUnits='[degF]')
            elif name == 'inlet': body.update(Reading=348.15, ReadingUnits='K', PhysicalContext='Intake', RelatedItem=[{'@odata.id': '/redfish/v1/Systems/1'}])
            elif name == 'other-node': body.update(Reading=120, RelatedItem=[{'@odata.id': '/redfish/v1/Systems/2/Processors/1'}])
            elif name == 'shared': body.update(Reading=82, PhysicalContext='Exhaust', RelatedItem=[])
            elif name == 'headroom': body.update(Reading=400, ReadingBasis='Headroom')
            elif name == 'disabled': body.update(Reading=400, Enabled=False)
            elif name == 'range': body.update(Reading=400, ReadingRangeMax=150)
            elif name == 'fan': body.update(Reading=20000, ReadingType='Rotational', ReadingUnits='RPM')
            elif name == 'unknown-health': body.update(Reading=400, PhysicalContext='Backplane'); body['Status']['Health'] = 'FutureHealth'
            self.reply(200, body)
        else:
            self.reply(404)

    def do_POST(self):
        self.user()
        data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        if self.path != '/redfish/v1/SessionService/Sessions':
            self.reply(404)
        elif data.get('Password') != 'test-secret':
            self.reply(401)
        else:
            token = secrets.token_hex(16)
            with lock:
                sessions[token] = data['UserName']
            self.reply(201, {'@odata.type': '#Session.v1_8_0.Session'}, [('X-Auth-Token', token), ('Location', '/redfish/v1/SessionService/Sessions/' + token)])

    def do_DELETE(self):
        user = self.user()
        token = self.headers.get('X-Auth-Token')
        if user == 'logout-failure':
            self.reply(500)
        elif user and self.path == '/redfish/v1/SessionService/Sessions/' + token:
            with lock:
                sessions.pop(token)
            self.reply(204)
        else:
            self.reply(401)


with tempfile.TemporaryDirectory(prefix='bcontrol-apple-discovery-') as directory:
    directory = Path(directory)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(directory / 'key.pem'), '-out', str(directory / 'ca.pem'),
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / 'ca.pem', directory / 'key.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    legacy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    legacy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    legacy_context.minimum_version = legacy_context.maximum_version = ssl.TLSVersion.TLSv1
    legacy_context.set_ciphers('DEFAULT:@SECLEVEL=0')
    legacy_context.load_cert_chain(directory / 'ca.pem', directory / 'key.pem')
    legacy.socket = legacy_context.wrap_socket(legacy.socket, server_side=True)
    legacy_worker = threading.Thread(target=legacy.serve_forever, daemon=True)
    legacy_worker.start()
    try:
        env = dict(os.environ, DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',
                   BC_TEST_REDFISH_LEGACY='https://localhost:' + str(legacy.server_port),
                   BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port), BC_TEST_REDFISH_CA=str(directory / 'ca.pem'))
        result = subprocess.run(['swift', 'test', '--package-path', str(root / 'frontends/apple'), '--scratch-path', str(root / 'build-apple'),
                                 '-Xcc', '-I', '-Xcc', str(root / 'include'),
                                 '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'), '-Xlinker', '-L', '-Xlinker', str(root / 'build'),
                                 '-Xlinker', '-rpath', '-Xlinker', str(root / 'build'), '--filter', 'DiscoveryTests|OverviewIntegrationTests'], env=env, timeout=120)
        if result.returncode == 0:
            assert list(sessions.values()) == ['logout-failure', 'logout-failure'], 'unexpected device sessions leaked'
            assert not any(auth for _, _, auth in calls), 'unexpected Basic fallback'
            assert sum(method == 'POST' for method, *_ in calls) == 18, 'login replay or missing test'
            assert sum(method == 'DELETE' for method, *_ in calls) == 17, 'owned session cleanup missing'
        raise SystemExit(result.returncode)
    finally:
        legacy.shutdown()
        legacy.server_close()
        legacy_worker.join(timeout=5)
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
