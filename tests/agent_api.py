import contextlib
import base64
import concurrent.futures
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import base64
import hashlib
import struct
import warnings

AGENT = str(Path(sys.argv.pop(1)).resolve())
VM_MEDIA = '/redfish/v1/Managers/mgr1/VirtualMedia/cd'
VM_INSERT = VM_MEDIA + '/Actions/InsertMedia'
VM_EJECT = VM_MEDIA + '/Actions/EjectMedia'
ORIGIN = 'https://frontend.example'


class Device(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.hits += 1
        if self.server.mode != 'legacy':
            if self.path == '/redfish/v1/':
                body = {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot', 'RedfishVersion': '1.17.0',
                        'TaskService': {'@odata.id': '/redfish/v1/work-queue'},
                        'Systems': {'@odata.id': '/redfish/v1/Systems'}, 'Chassis': {'@odata.id': '/redfish/v1/Chassis'}}
                if self.server.mode.startswith('session'):
                    body['Links'] = {'Sessions': {'@odata.id': '/redfish/v1/SessionService/FixtureSessions'}}
                self.reply(200, body)
            else:
                if self.path == '/redfish/v1/slow':
                    self.server.slow_started.set()
                    time.sleep(.3)
                basic = 'Basic ' + base64.b64encode(b'fixture-user:fixture-password').decode()
                authorized = (self.headers.get('X-Auth-Token') in self.server.sessions.values() or
                              self.headers.get('Authorization') == basic)
                if not authorized:
                    self.reply(401, {})
                elif self.path == '/redfish/v1/TaskService/Monitors/fixture':
                    self.reply(204, None)
                else:
                    self.reply(200, self.resource())
            return
        body = b'{"RedfishVersion":"1.17.0","Systems":{"@odata.id":"/redfish/v1/Systems"}}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def reply(self, status, body, headers=()):
        raw = json.dumps(body).encode() if body is not None else b''
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_PATCH(self):
        self.server.hits += 1
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        if self.path == '/redfish/v1/Systems/host' and self.headers.get('X-Auth-Token') in self.server.sessions.values():
            self.server.patch_bodies.append(body)
            if "Boot" in body:
                self.server.boot.update(body["Boot"])
            self.reply(200, dict(self.resource(), **body))
        else:
            self.reply(404, {})

    def do_POST(self):
        self.server.hits += 1
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        body = json.loads(raw) if raw else None
        if self.path == '/redfish/v1/Systems/host/Actions/FixtureVendorAction':
            if self.headers.get('X-Auth-Token') not in self.server.sessions.values():
                self.reply(401, {})
                return
            self.server.vendor_posts += 1
            self.reply(200, {'Echo': body})
            return
        if self.path == '/redfish/v1/Systems/host/Actions/FixtureReset':
            if self.headers.get('X-Auth-Token') not in self.server.sessions.values():
                self.reply(401, {})
                return
            self.server.reset_posts += 1
            if body == {'ResetType': 'On'}:
                self.server.power = 'On'
                self.reply(202, self.task(running=True), [('Location', '/redfish/v1/TaskService/Monitors/fixture'), ('Retry-After', '1')])
            elif body == {'ResetType': 'ForceOff'}:
                self.server.power = 'Off'
                self.reply(204, None)
            else:
                self.reply(400, {})
            return
        if self.path == VM_INSERT and body['Image'].startswith('http'):
            self.server.vm_posts.append(body)
            self.server.vm_image, self.server.vm_inserted = body['Image'], True
            if 'external.invalid' not in body['Image']:
                try:
                    fetch = urllib.request.Request(body['Image'], headers={'Range': 'bytes=100-199'})
                    with urllib.request.urlopen(fetch, timeout=5) as response:
                        self.server.vm_fetched = response.read()
                except OSError as error:
                    self.server.vm_error = str(error)
                    self.reply(500, {})
                    return
            self.reply(204, {})
            return
        if self.path == VM_EJECT:
            if self.server.vm_eject_failure:
                self.reply(500, {})
                return
            self.server.vm_ejects += 1
            if not self.server.vm_eject_noop:
                self.server.vm_inserted = False
            self.reply(204, {})
            return
        self.server.session_posts += 1
        if self.server.mode == 'session-denied':
            self.reply(401, {})
            return
        if (self.path != '/redfish/v1/SessionService/FixtureSessions' or
                self.headers.get('Authorization') or self.headers.get('X-Auth-Token') or
                body != {'UserName': 'fixture-user', 'Password': 'fixture-password'}):
            self.reply(400, {})
            return
        uri = self.path + '/' + secrets.token_hex(8)
        token = secrets.token_hex(16)
        self.server.sessions[uri] = token
        self.reply(201, {'@odata.type': '#Session.v1_8_0.Session', '@odata.id': uri},
                   [('X-Auth-Token', token), ('Location', uri)])

    def do_DELETE(self):
        self.server.hits += 1
        if self.server.sessions.get(self.path) != self.headers.get('X-Auth-Token') or self.path not in self.server.sessions:
            self.reply(403, {})
            return
        del self.server.sessions[self.path]
        self.server.session_deletes += 1
        self.reply(200, {})

    def task(self, running=False):
        return {'@odata.type': '#Task.v1_4_3.Task', '@odata.id': '/redfish/v1/TaskService/Tasks/fixture',
                'TaskState': 'Running' if running else 'Completed', 'TaskStatus': 'OK', 'PercentComplete': 33 if running else 100}

    def resource(self):
        resources = {
            '/redfish/v1/work-queue': {'@odata.type': '#TaskService.v1_2_0.TaskService', 'Tasks': {'@odata.id': '/redfish/v1/TaskService/Tasks'}},
            '/redfish/v1/TaskService/Tasks': {'@odata.type': '#TaskCollection.TaskCollection', 'Members': [{'@odata.id': '/redfish/v1/TaskService/Tasks/fixture'}]},
            '/redfish/v1/Systems': {'@odata.type': '#ComputerSystemCollection.ComputerSystemCollection', 'Members': [{'@odata.id': '/redfish/v1/Systems/host'}]},
            '/redfish/v1/Chassis': {'@odata.type': '#ChassisCollection.ChassisCollection', 'Members': [{'@odata.id': '/redfish/v1/Chassis/fixture'}]},
            '/redfish/v1/Chassis/fixture': {'@odata.type': '#Chassis.v1_22_0.Chassis', 'Sensors': {'@odata.id': '/redfish/v1/Chassis/fixture/Sensors'}},
            '/redfish/v1/Chassis/fixture/Sensors': {'@odata.type': '#SensorCollection.SensorCollection', 'Members': [{'@odata.id': '/redfish/v1/Chassis/fixture/Sensors/ambient'}]},
            '/redfish/v1/Chassis/fixture/Sensors/ambient': {'@odata.type': '#Sensor.v1_11_1.Sensor', 'Id': 'ambient', 'Reading': self.server.reading, 'ReadingUnits': 'Cel', 'ReadingType': 'Temperature'},
            '/redfish/v1/TaskService/Tasks/fixture': self.task(),
            '/redfish/v1/Managers/bmc': {'@odata.type': '#Manager.v1_15_0.Manager', 'Id': 'bmc',
                                          'VirtualMedia': {'@odata.id': '/redfish/v1/Managers/bmc/VirtualMedia'},
                                          'NetworkProtocol': {'@odata.id': '/redfish/v1/Managers/bmc/NetworkProtocol'},
                                          'EthernetInterfaces': {'@odata.id': '/redfish/v1/Managers/bmc/EthernetInterfaces'},
                                          'GraphicalConsole': {'ServiceEnabled': True, 'Port': 5900,
                                                               'ConnectTypesSupported': ['KVMIP']}},
            '/redfish/v1/Managers/bmc/NetworkProtocol': {'@odata.type': '#ManagerNetworkProtocol.v1_7_0.ManagerNetworkProtocol',
                                                          'HostName': 'fixture-bmc',
                                                          'SSH': {'ProtocolEnabled': True, 'Port': 22},
                                                          'HTTPS': {'ProtocolEnabled': True, 'Port': 443},
                                                          'IPMI': {'ProtocolEnabled': True, 'Port': 623}},
            '/redfish/v1/Managers/bmc/EthernetInterfaces': {'@odata.type': '#EthernetInterfaceCollection.EthernetInterfaceCollection',
                                                             'Members': [{'@odata.id': '/redfish/v1/Managers/bmc/EthernetInterfaces/eth0'}]},
            '/redfish/v1/Managers/bmc/EthernetInterfaces/eth0': {'@odata.type': '#EthernetInterface.v1_9_0.EthernetInterface',
                                                                  'Id': 'eth0', 'MACAddress': 'aa:bb:cc:dd:ee:ff',
                                                                  'Status': {'State': 'Enabled', 'Health': 'OK'},
                                                                  'DHCPv4': {'DHCPEnabled': True},
                                                                  'IPv4Addresses': [{'Address': '192.168.1.10',
                                                                                     'SubnetMask': '255.255.255.0',
                                                                                     'Gateway': '192.168.1.1',
                                                                                     'AddressOrigin': 'DHCP'}]},
            '/redfish/v1/Managers/bmc/VirtualMedia': {'@odata.type': '#VirtualMediaCollection.VirtualMediaCollection',
                                                       'Members': [{'@odata.id': VM_MEDIA}]},
            VM_MEDIA: {'@odata.type': '#VirtualMedia.v1_7_0.VirtualMedia', 'Id': 'cd', 'Name': 'CD',
                       'MediaTypes': ['CD'], 'Inserted': self.server.vm_inserted, 'Image': self.server.vm_image,
                       'ConnectedVia': 'URI' if self.server.vm_inserted else 'NotConnected',
                       'Actions': {'#VirtualMedia.InsertMedia': {'target': VM_INSERT},
                                   '#VirtualMedia.EjectMedia': {'target': VM_EJECT}}},
        }
        return resources.get(self.path, {'@odata.type': '#ComputerSystem.v1_22_0.ComputerSystem', 'Id': 'host',
                                         'Manufacturer': 'FixtureVendor', 'Model': 'FixtureModel',
                                         'PowerState': self.server.power, 'Boot': dict(self.server.boot),
                                         'Actions': {'#ComputerSystem.Reset': {'target': '/redfish/v1/Systems/host/Actions/FixtureReset',
                                                                             'ResetType@Redfish.AllowableValues': ['On', 'ForceOff']}}})


GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


class BMCWebSocket(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.received = b''
        self.error = ''

    def run(self):
        try:
            connection, _ = self.socket.accept()
            with connection:
                request = b''
                while b'\r\n\r\n' not in request:
                    request += connection.recv(4096)
                key = ''
                for line in request.split(b'\r\n'):
                    if line.lower().startswith(b'sec-websocket-key:'):
                        key = line.split(b':', 1)[1].strip()
                accept = base64.b64encode(hashlib.sha1(key + GUID.encode()).digest()).decode()
                connection.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                                    'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n').encode())
                connection.sendall(ws_encode(2, b'RFB 003.008\n'))
                while True:
                    frame = ws_decode(connection)
                    if frame is None:
                        break
                    opcode, payload = frame
                    if opcode == 8:
                        break
                    if opcode in (1, 2):
                        self.received += payload
        except OSError as error:
            self.error = str(error)
        finally:
            self.socket.close()


def ws_encode(opcode, payload):
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length <= 65535:
        header += bytes([126]) + length.to_bytes(2, 'big')
    else:
        header += bytes([127]) + length.to_bytes(8, 'big')
    return header + payload


def ws_decode(connection):
    head = connection.recv(2)
    if len(head) < 2:
        return None
    length = head[1] & 0x7f
    if length == 126:
        length = int.from_bytes(connection.recv(2), 'big')
    elif length == 127:
        length = int.from_bytes(connection.recv(8), 'big')
    mask = connection.recv(4) if head[1] & 0x80 else None
    payload = b''
    while len(payload) < length:
        chunk = connection.recv(length - len(payload))
        if not chunk:
            return None
        payload += chunk
    if mask:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(length))
    return head[0] & 15, payload


def ws_client(port, origin=ORIGIN):
    connection = socket.create_connection(('127.0.0.1', port), timeout=5)
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    connection.sendall((f'GET /v1/kvm/ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n'
                        f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
                        f'Origin: {origin}\r\n\r\n').encode())
    response = b''
    while b'\r\n\r\n' not in response:
        response += connection.recv(4096)
    if b' 101 ' not in response.split(b'\r\n')[0]:
        connection.close()
        raise OSError(response.decode(errors='replace'))
    return connection


def ws_send(connection, opcode, payload, final=True):
    mask = secrets.token_bytes(4)
    header = bytes([(0x80 if final else 0) | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([0x80 | length])
    elif length <= 65535:
        header += bytes([0x80 | 126]) + length.to_bytes(2, 'big')
    else:
        header += bytes([0x80 | 127]) + length.to_bytes(8, 'big')
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(length))
    connection.sendall(header + mask + masked)


class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 32


class AgentAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='bcontrol-agent-')
        cls.root = Path(cls.temp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.root / 'key'), '-out', str(cls.root / 'cert'), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, capture_output=True)
        (cls.root / 'server.pem').write_bytes((cls.root / 'cert').read_bytes() + (cls.root / 'key').read_bytes())
        cls.device = Server(('127.0.0.1', 0), Device)
        cls.device.hits = 0
        cls.device.mode = 'legacy'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.root / 'cert', cls.root / 'key')
        cls.device.socket = context.wrap_socket(cls.device.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.device.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.device.shutdown()
        cls.device.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    @contextlib.contextmanager
    def running(self, tls=False, device_mode='legacy', media=False, kvm_url=None, associated_device=None):
        self.device.mode = device_mode
        self.device.sessions = {}
        self.device.session_posts = self.device.session_deletes = 0
        self.device.reset_posts, self.device.power, self.device.reading = 0, 'On', 25.5
        self.device.vendor_posts, self.device.patch_bodies = 0, []
        self.device.boot = {'BootSourceOverrideEnabled': 'Disabled', 'BootSourceOverrideTarget': 'None',
                            'BootSourceOverrideMode': 'UEFI', 'BootSourceOverrideTarget@Redfish.AllowableValues': ['None', 'Cd', 'Pxe'],
                            'BootSourceOverrideEnabled@Redfish.AllowableValues': ['Disabled', 'Once']}

        self.device.vm_inserted, self.device.vm_image, self.device.vm_fetched = False, '', b''
        self.device.vm_ejects, self.device.vm_error, self.device.vm_posts = 0, '', []
        self.device.vm_eject_failure = False
        self.device.vm_eject_noop = False
        self.device.slow_started = threading.Event()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        pairing = self.root / ('pair-' + secrets.token_hex(8))
        args = [AGENT, 'serve', '--pairing-file', str(pairing), '--port', str(port), '--origin', ORIGIN, '--endpoint', 'https://localhost:' + str(self.device.server_port), '--ca', str(self.root / 'cert')]
        if tls:
            args += ['--tls-pem', str(self.root / 'server.pem')]
        self.media_port = None
        if media:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                self.media_port = sock.getsockname()[1]
            args += ['--media-listen', '127.0.0.1:' + str(self.media_port),
                     '--media-advertise', 'http://127.0.0.1:' + str(self.media_port)]
        if kvm_url:
            args += ['--kvm-url', kvm_url]
        if associated_device:
            args += ['--device-id', associated_device, '--kvm-device-id', associated_device]
        env = os.environ.copy()
        env.pop('BC_BMC_USERNAME', None)
        env.pop('BC_BMC_PASSWORD', None)
        if device_mode != 'legacy':
            env.update(BC_BMC_USERNAME='fixture-user', BC_BMC_PASSWORD='fixture-password')
        process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.port, self.tls = port, tls
        try:
            ready = False
            for _ in range(100):
                if process.poll() is not None:
                    self.fail(process.communicate()[1])
                try:
                    status, _, _ = self.call('GET', '/v1/health')
                    if status == 200:
                        ready = True
                        break
                except (OSError, json.JSONDecodeError):
                    pass
                time.sleep(.02)
            self.assertTrue(ready, 'Agent startup timed out')
            self.assertTrue(pairing.is_file())
            if os.name != 'nt':
                self.assertEqual(stat.S_IMODE(pairing.stat().st_mode), 0o600)
            yield pairing.read_text(), process
        finally:
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertFalse(pairing.exists())
            self.assertNotIn('"token"', stdout + stderr)

    def call(self, method, path, body=None, token=None, origin=None, raw=None, headers=None):
        h = dict(headers or {})
        if token:
            h['Authorization'] = 'Bearer ' + token
        if origin:
            h['Origin'] = origin
        if body is not None:
            raw = json.dumps(body)
            h['Content-Type'] = 'application/json'
        if self.tls:
            context = ssl.create_default_context(cafile=str(self.root / 'cert'))
            connection = http.client.HTTPSConnection('127.0.0.1', self.port, context=context, timeout=5)
        else:
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            connection.request(method, path, raw, h)
            response = connection.getresponse()
            data = response.read()
            return response.status, json.loads(data), dict(response.getheaders())
        finally:
            connection.close()

    def test_pairing_revocation_and_device_access(self):
        with self.running() as (secret, _):
            baseline = self.device.hits
            self.assertEqual(self.call('POST', '/v1/request', {'path': '/redfish/v1/'})[0], 401)
            self.assertEqual(self.device.hits, baseline)
            self.assertEqual(self.call('POST', '/v1/pair', {'secret': '0' * 64, 'name': 'bad'})[0], 401)
            status, first, _ = self.call('POST', '/v1/pair', {'secret': secret, 'name': 'desktop'}, origin=ORIGIN)
            self.assertEqual(status, 201)
            self.assertEqual(self.call('POST', '/v1/pair', {'secret': secret, 'name': 'replay'})[0], 401)
            token = first['token']
            status, response, _ = self.call('POST', '/v1/request', {'path': '/redfish/v1/'}, token=token)
            self.assertEqual(status, 200)
            self.assertEqual(response['status'], 'ok')
            self.assertTrue(response['peer_verified'])
            self.assertEqual(response['body']['RedfishVersion'], '1.17.0')
            self.assertEqual(self.device.hits, baseline + 1)
            status, invitation, _ = self.call('POST', '/v1/pairing', token=token)
            self.assertEqual(status, 201)
            status, second, _ = self.call('POST', '/v1/pair', {'secret': invitation['secret'], 'name': 'web'})
            self.assertEqual(status, 201)
            status, clients, _ = self.call('GET', '/v1/clients', token=token)
            self.assertEqual(status, 200)
            self.assertEqual(len(clients), 2)
            self.assertFalse(any('token' in item for item in clients))
            status, unconsumed, _ = self.call('POST', '/v1/pairing', token=second['token'])
            self.assertEqual(status, 201)
            self.assertEqual(self.call('DELETE', '/v1/clients/' + second['client_id'], token=token)[0], 200)
            self.assertEqual(self.call('GET', '/v1/clients', token=second['token'])[0], 401)
            self.assertEqual(self.call('POST', '/v1/pair', {'secret': unconsumed['secret'], 'name': 'revoked-invitation'})[0], 401)
            self.assertEqual(self.call('GET', '/v1/clients', token=token)[0], 200)
            self.assertEqual(self.call('POST', '/v1/request', {'path': 'https://different.invalid'}, token=token)[0], 400)

    def test_origin_json_and_host_boundaries(self):
        with self.running() as (secret, _):
            self.assertEqual(self.call('GET', '/v1/health', origin='https://evil.example')[0], 403)
            self.assertEqual(self.call('GET', '/v1/health', headers={'Host': 'evil.example'})[0], 400)
            self.assertEqual(self.call('GET', '/v1/health?token=hidden')[0], 400)
            for framing in ('Content-Length: 5x\r\n', 'Content-Length: +5\r\n', 'Transfer-Encoding: chunked\r\nContent-Length: 5\r\n'):
                with socket.create_connection(('127.0.0.1', self.port), timeout=3) as sock:
                    request = 'POST /v1/pair HTTP/1.1\r\nHost: 127.0.0.1:' + str(self.port) + '\r\n' + framing + '\r\n'
                    sock.sendall(request.encode())
                    status_line = sock.recv(4096).split(b'\r\n', 1)[0]
                    self.assertIn(status_line.split()[1], (b'400', b'411'))
            status, _, headers = self.call('OPTIONS', '/v1/pair', origin=ORIGIN)
            self.assertEqual(status, 200)
            self.assertEqual(headers['Access-Control-Allow-Origin'], ORIGIN)
            self.assertEqual(self.call('POST', '/v1/pair', raw='{}', headers={'Content-Type': 'text/plain'})[0], 400)
            duplicate = json.dumps({'secret': secret, 'name': 'first'})[:-1] + ',"name":"second"}'
            self.assertEqual(self.call('POST', '/v1/pair', raw=duplicate, headers={'Content-Type': 'application/json'})[0], 400)
            self.assertEqual(self.call('POST', '/v1/pair', {'secret': secret, 'name': 'ok'})[0], 201)

    def test_agent_https_is_separate(self):
        with self.running(tls=True) as (secret, _):
            self.assertEqual(self.call('POST', '/v1/pair', {'secret': secret, 'name': 'tls'})[0], 201)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_1
            context.set_ciphers('AES128-SHA:@SECLEVEL=0')
            with socket.create_connection(('127.0.0.1', self.port), timeout=3) as sock:
                with self.assertRaises(ssl.SSLError):
                    context.wrap_socket(sock, server_hostname='localhost')

    def paired(self, secret, name='desktop'):
        status, client, _ = self.call('POST', '/v1/pair', {'secret': secret, 'name': name})
        self.assertEqual(status, 201)
        return client

    def test_explicit_kvm_management_association(self):
        for device in (None, 'rack-1'):
            with self.subTest(device=device), self.running(device_mode='session',
                    kvm_url='ws://127.0.0.1:9/console', associated_device=device) as (secret, _):
                token = self.paired(secret)['token']
                status, ticket, _ = self.call('POST', '/v1/kvm/tickets', token=token)
                self.assertEqual(status, 201)
                self.assertEqual(ticket.get('management_device_id'), device)
                status, failure, _ = self.call('POST', '/v1/connections',
                    {'mode': 'auto', 'device_id': 'wrong-device'}, token=token)
                self.assertEqual(status, 409)
                self.assertEqual(failure['error'], 'device_association_mismatch')
                self.assertEqual(self.device.session_posts, 0)
                expected = device or 'default'
                status, connection, _ = self.call('POST', '/v1/connections',
                    {'mode': 'auto', 'device_id': expected}, token=token)
                self.assertEqual(status, 201)
                self.assertEqual(connection['device_id'], expected)
                self.assertEqual(self.call('DELETE', '/v1/connections/' + connection['connection_id'], token=token)[0], 200)

    def test_connection_session_reuse_owner_isolation_and_basic_fallback(self):
        for mode in ('session', 'absent'):
            with self.subTest(mode=mode), self.running(device_mode=mode) as (secret, _):
                first = self.paired(secret)
                token = first['token']
                _, invitation, _ = self.call('POST', '/v1/pairing', token=token)
                second = self.paired(invitation['secret'], 'web')
                self.assertEqual(self.call('POST', '/v1/connections', {'mode': 'auto'})[0], 401)
                for invalid in ({'mode': 'unknown'}, {'mode': 'auto', 'origin': 'https://other.invalid'}):
                    self.assertEqual(self.call('POST', '/v1/connections', invalid, token=token)[0], 400)
                status, result, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
                self.assertEqual(status, 201)
                self.assertEqual(result['status'], 'ok')
                self.assertEqual(result['authentication'], 'session' if mode == 'session' else 'basic')
                self.assertEqual(result['flags'], 2 if mode == 'session' else 1)
                self.assertTrue(result['endpoint_revision'].isdigit())
                route = '/v1/connections/' + result['connection_id']
                self.assertEqual(self.call('GET', '/v1/connections', token=second['token'])[1], [])
                before = self.device.hits
                self.assertEqual(self.call('POST', route + '/request', {'path': '/redfish/v1/Systems/host'}, token=second['token'])[0], 404)
                self.assertEqual(self.call('DELETE', route, token=second['token'])[0], 404)
                self.assertEqual(self.device.hits, before)
                for _ in range(2):
                    status, read, _ = self.call('POST', route + '/request', {'path': '/redfish/v1/Systems/host'}, token=token)
                    self.assertEqual(status, 200)
                    self.assertEqual(read['http_status'], 200)
                    self.assertTrue(read['peer_verified'])
                    self.assertEqual(read['body']['PowerState'], 'On')
                self.assertEqual(self.device.session_posts, 1 if mode == 'session' else 0)
                for invalid in ('https://other.invalid', '/redfish/v1/../../outside', '/redfish/v1/%2e%2e/outside'):
                    self.assertEqual(self.call('POST', route + '/request', {'path': invalid}, token=token)[0], 400)
                self.assertEqual(len(self.call('GET', '/v1/connections', token=token)[1]), 1)
                for remote_token in self.device.sessions.values():
                    self.assertNotIn(remote_token, json.dumps(result))
                status, closed, _ = self.call('DELETE', route, token=token)
                self.assertEqual((status, closed['status']), (200, 'ok'))
                self.assertEqual(self.call('GET', '/v1/connections', token=token)[1], [])
                self.assertEqual(self.device.sessions, {})
                self.assertEqual(self.device.session_deletes, 1 if mode == 'session' else 0)

    def test_connection_busy_revocation_and_shutdown_cleanup(self):
        with self.running(device_mode='session') as (secret, _):
            first = self.paired(secret)
            token = first['token']
            _, invite, _ = self.call('POST', '/v1/pairing', token=token)
            second = self.paired(invite['secret'], 'web')
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'session'}, token=token)
            route = '/v1/connections/' + connected['connection_id']
            with concurrent.futures.ThreadPoolExecutor() as executor:
                pending = executor.submit(self.call, 'POST', route + '/request', {'path': '/redfish/v1/slow'}, token)
                self.assertTrue(self.device.slow_started.wait(3))
                self.assertEqual(self.call('POST', route + '/request', {'path': '/redfish/v1/Systems/host'}, token=token)[0], 409)
                self.assertEqual(self.call('DELETE', '/v1/clients/' + first['client_id'], token=second['token'])[0], 200)
                self.assertEqual(pending.result(timeout=5)[0], 401)
            for _ in range(100):
                if not self.device.sessions:
                    break
                time.sleep(.02)
            self.assertEqual(self.device.sessions, {})
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=second['token'])
            self.assertEqual(connected['status'], 'ok')
            self.assertEqual(len(self.device.sessions), 1)
        self.assertEqual(self.device.sessions, {})
        self.assertEqual(self.device.session_deletes, 2)

    def test_revocation_and_shutdown_preserve_remote_media(self):
        for revoke in (True, False):
            with self.subTest(revoke=revoke):
                with self.running(device_mode='session') as (secret, _):
                    first = self.paired(secret)
                    token = first['token']
                    _, invite, _ = self.call('POST', '/v1/pairing', token=token)
                    second = self.paired(invite['secret'], 'web')
                    _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
                    route = '/v1/connections/' + connected['connection_id']
                    mapped = self.call('POST', route + '/media',
                        {'media_uri': VM_MEDIA, 'image_url': 'http://external.invalid/image.iso'}, token=token)[1]
                    self.assertEqual(mapped['status'], 'ok')
                    self.assertTrue(self.device.vm_inserted)
                    if revoke:
                        self.assertEqual(self.call('DELETE', '/v1/clients/' + first['client_id'], token=second['token'])[0], 200)
                        deadline = time.monotonic() + 5
                        while self.device.sessions and time.monotonic() < deadline:
                            time.sleep(.02)
                        self.assertEqual(self.device.sessions, {})
                self.assertTrue(self.device.vm_inserted)
                self.assertEqual(self.device.vm_ejects, 0)
                self.assertEqual(self.device.session_deletes, 1)

    def test_connection_limit_and_failed_login_release(self):
        with self.running(device_mode='session-denied') as (secret, _):
            token = self.paired(secret)['token']
            status, result, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            self.assertEqual((status, result['status'], result['http_status']), (200, 'http_error', 401))
            self.assertEqual(result['flags'], 0)
            self.assertEqual(self.call('GET', '/v1/connections', token=token)[1], [])
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            for _ in range(8):
                self.assertEqual(self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)[0], 201)
            hits = self.device.hits
            self.assertEqual(self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)[0], 409)
            self.assertEqual(self.device.hits, hits)
        self.assertEqual(self.device.sessions, {})
        self.assertEqual(self.device.session_deletes, 8)

    def test_media_mapping_routes_and_cleanup(self):
        image = self.root / 'image.iso'
        image.write_bytes(bytes(range(256)) * 4096)
        with self.running(device_mode='session', media=True) as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            route = '/v1/connections/' + connected['connection_id']
            status, mapped, _ = self.call('POST', route + '/media',
                                          {'media_uri': VM_MEDIA, 'file': str(image)}, token=token)
            self.assertEqual((status, mapped['status'], mapped['http_status']), (200, 'ok', 204))
            self.assertTrue(mapped['url'].startswith('http://127.0.0.1:' + str(self.media_port) + '/media/'))
            self.assertEqual(self.device.vm_fetched, image.read_bytes()[100:200])
            self.assertEqual(self.device.vm_image, mapped['url'])
            status, ejected, _ = self.call('DELETE', route + '/media', token=token)
            self.assertEqual((status, ejected['status']), (200, 'ok'))
            self.assertEqual(self.device.vm_ejects, 1)
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(mapped['url'], timeout=5)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()
            self.assertEqual(self.call('DELETE', route + '/media', token=token)[0], 404)
            status, mapped, _ = self.call('POST', route + '/media',
                                          {'media_uri': VM_MEDIA, 'file': str(image)}, token=token)
            self.assertEqual((status, mapped['status']), (200, 'ok'))
            self.assertEqual(self.call('DELETE', route, token=token)[0], 200)
            self.assertEqual(self.device.vm_ejects, 2)
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(mapped['url'], timeout=5)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            row = self.call('POST', '/v1/connections/' + connected['connection_id'] + '/media',
                            {'media_uri': VM_MEDIA, 'file': str(image)}, token=token)[1]
            self.assertEqual(row['status'], 'unsupported')

    def test_kvm_proxy_ticket_and_byte_bridge(self):
        bmc = BMCWebSocket()
        bmc.start()
        try:
            with self.running(device_mode='legacy', kvm_url='ws://127.0.0.1:' + str(bmc.port) + '/kvm') as (secret, _):
                token = self.paired(secret)['token']
                status, ticket, _ = self.call('POST', '/v1/kvm/tickets', {}, token=token)
                self.assertEqual((status, ticket['websocket_path']), (201, '/v1/kvm/ws'))
                self.assertEqual(ticket['input_version'], 1)
                connection = ws_client(self.port)
                try:
                    ws_send(connection, 1, json.dumps({'ticket': ticket['ticket']}).encode())
                    kind, payload = ws_decode(connection)
                    self.assertEqual((kind, json.loads(payload)), (1, {'type': 'ready', 'input_capabilities': 1}))
                    kind, payload = ws_decode(connection)
                    self.assertEqual((kind, payload), (2, b'RFB 003.008\n'))
                    ws_send(connection, 2, b'client-to-bmc')
                    for _ in range(50):
                        if b'client-to-bmc' in bmc.received:
                            break
                        time.sleep(.02)
                    self.assertIn(b'client-to-bmc', bmc.received)
                    events = [
                        {'type': 'key', 'keysym': 0xff0d, 'down': True},
                        {'type': 'scroll', 'buttons': 2, 'x': 1, 'y': 2, 'width': 3, 'height': 4, 'wheel': -1},
                        {'type': 'chord', 'keys': [0xffe3, 0xffff]},
                    ]
                    for event in events:
                        ws_send(connection, 1, json.dumps({'type': 'input', 'event': event}).encode())
                    expected = bytes.fromhex('040100000000ff0d 051400010002 050400010002 '
                                             '040100000000ffe3 040100000000ffff 040000000000ffff 040000000000ffe3')
                    for _ in range(50):
                        if expected in bmc.received:
                            break
                        time.sleep(.02)
                    self.assertIn(expected, bmc.received)
                    invalid = {'type': 'pointer', 'buttons': 8, 'x': 0, 'y': 0, 'width': 3, 'height': 4}
                    ws_send(connection, 1, json.dumps({'type': 'input', 'event': invalid}).encode())
                    kind, payload = ws_decode(connection)
                    self.assertEqual((kind, payload), (8, bytes.fromhex('03f0')))
                finally:
                    connection.close()
                status, second, _ = self.call('POST', '/v1/kvm/tickets', {}, token=token)
                self.assertEqual(status, 201)
                first = ws_client(self.port)
                replay = ws_client(self.port)
                try:
                    ws_send(first, 1, json.dumps({'ticket': second['ticket']}).encode())
                    self.assertEqual(json.loads(ws_decode(first)[1]), {'type': 'ready', 'input_capabilities': 1})
                    ws_send(replay, 1, json.dumps({'ticket': second['ticket']}).encode())
                    frame = ws_decode(replay)
                    self.assertTrue(frame is None or frame[0] == 8)
                finally:
                    first.close()
                    replay.close()
        finally:
            bmc.join(timeout=5)

    def test_kvm_shutdown_with_active_fragment(self):
        connection = None
        try:
            with self.running(device_mode='legacy', kvm_url='ws://127.0.0.1:1/kvm'):
                connection = ws_client(self.port)
                ws_send(connection, 1, b'{"ticket":', final=False)
                ws_send(connection, 9, b'fragment-stored')
                self.assertEqual(ws_decode(connection), (10, b'fragment-stored'))
            self.assertEqual(connection.recv(1), b'')
        finally:
            if connection:
                connection.close()

    def test_direct_media_url_route(self):
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            route = '/v1/connections/' + connected['connection_id']
            status, mapped, _ = self.call('POST', route + '/media',
                                          {'media_uri': VM_MEDIA, 'image_url': 'http://external.invalid/image.iso',
                                           'transfer_method': 'Stream', 'transfer_protocol_type': 'HTTP'}, token=token)
            self.assertEqual((status, mapped['status'], mapped['http_status']), (200, 'ok', 204))
            self.assertEqual(mapped['url'], 'http://external.invalid/image.iso')
            self.assertEqual(self.device.vm_image, 'http://external.invalid/image.iso')
            self.assertEqual(self.device.vm_posts[-1], {'Image': 'http://external.invalid/image.iso', 'Inserted': True,
                                                        'TransferMethod': 'Stream', 'TransferProtocolType': 'HTTP'})
            status_code, ejected, _ = self.call('DELETE', route + '/media', token=token)
            self.assertEqual((status_code, ejected['status']), (200, 'ok'), ejected)
            self.assertEqual(self.device.vm_ejects, 1, ejected)
            self.assertEqual(self.call('POST', route + '/media', {'media_uri': VM_MEDIA}, token=token)[0], 400)

    def test_media_eject_failure_retains_mount_and_survives_logout(self):
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            route = '/v1/connections/' + connected['connection_id']
            mount = {'media_uri': VM_MEDIA, 'image_url': 'http://external.invalid/image.iso'}
            self.assertEqual(self.call('POST', route + '/media', mount, token=token)[1]['status'], 'ok')
            self.device.vm_eject_failure = True
            failed = self.call('DELETE', route + '/media', token=token)[1]
            self.assertNotEqual(failed['status'], 'ok')
            self.assertEqual(self.call('POST', route + '/media', mount, token=token)[0], 409)
            self.device.vm_eject_failure = False
            self.device.vm_eject_noop = True
            self.assertEqual(self.call('DELETE', route + '/media', token=token)[1]['status'], 'outcome_unknown')
            self.assertEqual(self.call('POST', route + '/media', mount, token=token)[0], 409)
            self.device.vm_eject_noop = False
            self.assertEqual(self.call('DELETE', route + '/media', token=token)[1]['status'], 'ok')
            self.assertEqual(self.call('POST', route + '/media', mount, token=token)[1]['status'], 'ok')
            self.device.vm_eject_failure = True
            closed = self.call('DELETE', route, token=token)[1]
            self.assertEqual(closed['status'], 'ok')
            self.assertNotIn('media_cleanup_status', closed)
            self.assertTrue(self.device.vm_inserted)
            self.assertEqual(self.device.session_deletes, 1)
            _, restored, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            self.assertEqual(restored['managed_media_uri'], VM_MEDIA)
            self.assertTrue(restored['remote_media_retained'])
            route = '/v1/connections/' + restored['connection_id']
            self.device.vm_eject_failure = False
            self.assertEqual(self.call('DELETE', route + '/media', token=token)[1]['status'], 'ok')
            self.assertFalse(self.device.vm_inserted)

    def test_manual_media_eject_protects_active_connection_and_preserves_original_owner(self):
        with self.running(device_mode='session') as (secret, _):
            first = self.paired(secret)
            _, invite, _ = self.call('POST', '/v1/pairing', token=first['token'])
            other = self.paired(invite['secret'], 'manual')
            _, a, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=first['token'])
            _, b, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=other['token'])
            route_a, route_b = '/v1/connections/' + a['connection_id'], '/v1/connections/' + b['connection_id']
            mount = {'media_uri': VM_MEDIA, 'image_url': 'http://external.invalid/image.iso'}
            self.assertEqual(self.call('POST', route_a + '/media', mount, token=first['token'])[1]['status'], 'ok')
            self.assertEqual(self.call('DELETE', route_b + '/media', {'media_uri': VM_MEDIA}, token=other['token'])[1]['status'], 'busy')
            self.assertEqual(self.device.vm_ejects, 0)
            self.assertEqual(self.call('DELETE', route_a, token=first['token'])[1]['status'], 'ok')
            self.device.vm_eject_failure = True
            self.assertNotEqual(self.call('DELETE', route_b + '/media', {'media_uri': VM_MEDIA}, token=other['token'])[1]['status'], 'ok')
            self.assertEqual(self.call('DELETE', route_b, token=other['token'])[1]['status'], 'ok')
            _, restored, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=first['token'])
            self.assertEqual(restored['managed_media_uri'], VM_MEDIA)
            self.device.vm_eject_failure = False
            route = '/v1/connections/' + restored['connection_id']
            self.assertEqual(self.call('DELETE', route + '/media', token=first['token'])[1]['status'], 'ok')
            self.assertEqual(self.call('DELETE', route, token=first['token'])[1]['status'], 'ok')
            _, empty, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=other['token'])
            before = self.device.vm_ejects
            self.assertEqual(self.call('DELETE', '/v1/connections/' + empty['connection_id'] + '/media',
                                      {'media_uri': VM_MEDIA}, token=other['token'])[1]['status'], 'ok')
            self.assertEqual(self.device.vm_ejects, before)

    def test_virtual_media_discovery_query(self):
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            status, row, _ = self.call('POST', '/v1/connections/' + connected['connection_id'] + '/query',
                                       {'operation': 'virtual-media', 'uri': '/redfish/v1/Managers/bmc'}, token=token)
            self.assertEqual((status, row['status']), (200, 'ok'))
            self.assertEqual(row['members'], [VM_MEDIA])
            _, state, _ = self.call('POST', '/v1/connections/' + connected['connection_id'] + '/query',
                {'operation': 'virtual-media-info', 'uri': VM_MEDIA}, token=token)
            self.assertEqual(state['status'], 'ok')
            self.assertIs(state['media']['inserted'], False)
            self.assertEqual(state['media']['flags'] & 12, 12)
            self.assertIn('CD', state['media']['media_types'])

    def test_graphical_console_query(self):
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            status, row, _ = self.call('POST', '/v1/connections/' + connected['connection_id'] + '/query',
                                       {'operation': 'graphical-console', 'uri': '/redfish/v1/Managers/bmc'}, token=token)
            self.assertEqual((status, row['status']), (200, 'ok'))
            self.assertEqual((row['graphical_console']['service_enabled'], row['graphical_console']['port']), (True, 5900))
            self.assertEqual(row['graphical_console']['connect_types'], ['KVMIP'])

    def test_network_readonly_queries(self):
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            route = '/v1/connections/' + connected['connection_id'] + '/query'
            status, row, _ = self.call('POST', route, {'operation': 'network-protocol', 'uri': '/redfish/v1/Managers/bmc'}, token=token)
            self.assertEqual((status, row['status']), (200, 'ok'))
            protocols = {entry['name']: entry for entry in row['network_protocol']['protocols']}
            self.assertEqual(protocols['SSH'], {'name': 'SSH', 'enabled': True, 'port': 22})
            self.assertEqual(protocols['IPMI'], {'name': 'IPMI', 'enabled': True, 'port': 623})
            self.assertEqual(protocols['NTP'], {'name': 'NTP'})
            self.assertEqual(protocols['SNMP'], {'name': 'SNMP'})
            status, row, _ = self.call('POST', route, {'operation': 'ethernet-interfaces', 'uri': '/redfish/v1/Managers/bmc'}, token=token)
            self.assertEqual((status, row['status']), (200, 'ok'))
            member = row['members'][0]
            status, row, _ = self.call('POST', route, {'operation': 'ethernet-interface', 'uri': member}, token=token)
            self.assertEqual((status, row['status']), (200, 'ok'))
            info = row['ethernet_interface']
            self.assertEqual(info['mac'], 'aa:bb:cc:dd:ee:ff')
            self.assertEqual(info['state'], 'Enabled')
            self.assertEqual(info['dhcp4_enabled'], True)
            self.assertEqual(info['ipv4_addresses'][0]['address'], '192.168.1.10')
            status, row, _ = self.call('POST', route, {'operation': 'managers'}, token=token)
            self.assertEqual((status, row['status']), (200, 'unsupported'))

    def test_vendor_action_and_patch(self):
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            route = '/v1/connections/' + connected['connection_id'] + '/request'
            status, result, _ = self.call('POST', route, {'path': '/redfish/v1/Systems/host/Actions/FixtureVendorAction',
                'method': 'POST', 'body': {'Mode': 'next'}}, token=token)
            self.assertEqual((status, result['status'], result['http_status']), (200, 'ok', 200))
            self.assertEqual(result['body'], {'Echo': {'Mode': 'next'}})
            status, result, _ = self.call('POST', route, {'path': '/redfish/v1/Systems/host',
                'method': 'PATCH', 'body': {'AssetTag': 'vendor'}}, token=token)
            self.assertEqual((status, result['body']['AssetTag']), (200, 'vendor'))
            self.assertEqual(self.device.vendor_posts, 1)
            self.assertEqual(self.device.patch_bodies, [{'AssetTag': 'vendor'}])
            self.assertEqual(self.call('POST', route, {'path': '/redfish/v1/Systems/host', 'method': 'PATCH'}, token=token)[0], 400)
            self.assertEqual(self.call('POST', route, {'path': '/redfish/v1/Systems/host', 'method': 'GET', 'body': {}}, token=token)[0], 400)
            self.assertEqual(self.call('POST', route, {'path': '/redfish/v1/Systems/host', 'method': 'TRACE'}, token=token)[0], 400)

    def test_typed_queries_and_capability_checked_power(self):
        with self.running(device_mode='session') as (secret, _):
            token = self.paired(secret)['token']
            _, connected, _ = self.call('POST', '/v1/connections', {'mode': 'auto'}, token=token)
            route = '/v1/connections/' + connected['connection_id']

            def query(operation, uri=None):
                body = {'operation': operation}
                if uri:
                    body['uri'] = uri
                status, result, _ = self.call('POST', route + '/query', body, token=token)
                self.assertEqual((status, result['status']), (200, 'ok'))
                return result

            probe = query('probe')
            self.assertEqual(probe['redfish_version'], '1.17.0')
            self.assertTrue(probe['flags'] & 3)
            task_uri = query('tasks')['members'][0]
            self.assertEqual(query('task', task_uri)['task']['state'], 'Completed')
            uri = query('systems')['members'][0]
            self.assertEqual(query('system', uri)['power_state'], 'On')
            self.assertEqual(query('system', uri)['identity']['manufacturer'], 'FixtureVendor')
            self.assertEqual(query('reset-capabilities', uri)['reset']['supported_actions'], ['On', 'ForceOff'])
            chassis = query('chassis')['members'][0]
            sensor = query('sensors', chassis)['members'][0]
            self.assertEqual(query('sensor', sensor)['sensor']['reading'], 25.5)
            sensor_details = query('sensor-details', sensor)['sensor_details']
            self.assertEqual(sensor_details['reading'], 25.5)
            self.assertEqual(sensor_details['fields']['states']['state'], 'unsupported')
            self.device.reading = None
            self.assertIsNone(query('sensor', sensor)['sensor']['reading'])
            for action, expected in [('GracefulShutdown', 'unsupported'), ('ForceOff', 'ok'), ('On', 'ok')]:
                before = self.device.reset_posts
                status, result, _ = self.call('POST', route + '/power', {'uri': uri, 'action': action}, token=token)
                self.assertEqual((status, result['status']), (200, expected))
                if action == 'GracefulShutdown':
                    self.assertEqual(self.device.reset_posts, before)
                elif action == 'ForceOff':
                    self.assertEqual(result['flags'], 1)
                    self.assertEqual(query('system', uri)['power_state'], 'Off')
                else:
                    self.assertEqual(result['flags'], 3)
                    self.assertEqual(result['task']['retry_after'], '1')
                    task = query('task', result['task']['task_uri'])['task']
                    self.assertEqual((task['state'], task['percent_complete']), ('Completed', 100))
                    monitor = query('task-monitor', result['task']['monitor_uri'])['task']
                    self.assertEqual(monitor['flags'], 2)
                    self.assertIsNone(monitor['percent_complete'])
            before = self.device.hits
            for body in ({'operation': 'reset', 'uri': uri}, {'operation': 'systems', 'uri': uri}, {'operation': 'tasks', 'uri': uri}, {'operation': 'sensor'}):
                self.assertEqual(self.call('POST', route + '/query', body, token=token)[0], 400)
            self.assertEqual(self.call('POST', route + '/power', {'uri': uri, 'action': 'invented'}, token=token)[0], 400)
            self.assertEqual(self.device.hits, before)
            self.assertEqual(self.device.session_posts, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
