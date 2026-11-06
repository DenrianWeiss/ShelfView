import base64
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

from inspur_fixture import PAGE, SCRIPT, SCRIPT_NEGOTIATED

CLIENT = str(Path(sys.argv.pop(1)).resolve())
USER, PASSWORD, TOKEN = 'fixture-user', 'quote"\\password', 'fixture-session-token'
SESSIONS = '/redfish/v1/SessionService/CustomSessions'
OWN = SESSIONS + '/owned'
ROOT = {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot'}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body=None, headers=()):
        body = b'' if body is None else body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def auth(self):
        basic = self.headers.get('Authorization')
        token = self.headers.get('X-Auth-Token')
        if basic and token:
            return 'mixed'
        if basic:
            return 'basic' if basic == 'Basic ' + base64.b64encode((USER + ':' + PASSWORD).encode()).decode() else 'invalid'
        if token:
            return 'token' if token == TOKEN and self.server.active else 'invalid'
        return 'none'

    def record(self):
        auth = self.auth()
        self.server.calls.append((self.command, self.path, auth, bool(self.headers.get('Cookie'))))
        return auth

    def do_GET(self):
        auth = self.record()
        mode = self.server.mode
        if mode.startswith('inspur') and self.path in ('/index.html', '/js/signin.js'):
            self.reply(200, PAGE if self.path == '/index.html' else
                       {'inspur': SCRIPT, 'inspur-public': SCRIPT_NEGOTIATED}.get(mode, b'unknown')); return
        if mode in ('inspur-public', 'inspur-public-unknown') and self.path == '/redfish/v1/':
            self.reply(200, dict(ROOT, RedfishVersion='1.0.2',
                                 Links={'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}})); return
        if mode.startswith('inspur') and self.path == '/redfish/v1/' and auth == 'none':
            self.reply(500); return
        if self.path == '/redfish/v1/Chassis':
            self.reply(200, {'@odata.type': '#ChassisCollection.ChassisCollection', 'Members': ['/redfish/v1/Chassis/one']}); return
        if self.path == '/redfish/v1/Chassis/one':
            wrong_link = '/Thermal' if mode == 'inspur-public' else '/NetworkAdapters'
            self.reply(200, {'@odata.type': '#Chassis.v1_2_0.Chassis', '@odata.id': self.path,
                            'Links': {'ComputerSystems': [{'@odata.id': self.path + wrong_link}]}}); return
        if self.path == '/redfish/v1/Chassis/one/Thermal':
            self.reply(200, {'@odata.type': '#Thermal.v1_0_2.Thermal',
                            'Temperatures': [{'ReadingCelsius': 23, 'Status': {'State': 'ENABLE'}}],
                            'Fans': [{'Speed': '5280'}]}); return
        if self.path == '/redfish/v1/':
            body = dict(ROOT)
            if mode not in ('absent', 'basic-only'):
                if mode.startswith('service-'):
                    body['SessionService'] = {'@odata.id': '/redfish/v1/SessionService'}
                else:
                    body['Links'] = {'Sessions': {'@odata.id': SESSIONS}}
            if mode == 'basic-only' and auth != 'basic':
                self.reply(401)
            else:
                self.reply(200, body)
        elif self.path == '/redfish/v1/SessionService':
            if mode == 'service-401':
                self.reply(401)
            else:
                self.reply(200, {'@odata.type': '#SessionService.v1_2_0.SessionService',
                                 'ServiceEnabled': False if mode == 'service-disabled' else None,
                                 'Sessions': {'@odata.id': SESSIONS}})
        elif self.path == '/redfish/v1/Systems/system':
            if auth in ('basic', 'token'):
                self.reply(200, {'@odata.type': '#ComputerSystem.v1_20_0.ComputerSystem',
                                 'Id': 'system', 'Name': 'fixture', 'PowerState': 'On'})
            else:
                self.reply(401)
        else:
            self.reply(404)

    def drop(self):
        self.close_connection = True
        self.connection.shutdown(socket.SHUT_RDWR)
        self.connection.close()

    def do_POST(self):
        auth = self.record()
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        self.server.login_valid = auth == 'none' and body == {'UserName': USER, 'Password': PASSWORD}
        mode = self.server.mode
        expected = '/redfish/v1/SessionService/Sessions' if mode.startswith('inspur') else SESSIONS
        if self.path != expected or not self.server.login_valid:
            self.reply(400)
            return
        if mode.startswith('post-'):
            self.reply(int(mode[5:]), {'error': {'code': 'fixture.error'}})
            return
        self.server.active = True
        if mode == 'drop-login':
            self.drop()
            return
        location = 'https://other.invalid/redfish/v1/Sessions/stolen' if mode == 'foreign-location' else OWN
        if mode == 'absolute-location': location = f'https://LOCALHOST:{self.server.server_port}' + OWN
        if mode == 'wrong-port-location': location = 'https://localhost' + OWN
        headers = [('Location', location), ('Set-Cookie', 'unused=fixture; Secure; HttpOnly')]
        if mode != 'missing-token':
            headers.append(('X-Auth-Token', TOKEN))
        if mode == 'missing-location':
            headers = [(k, v) for k, v in headers if k != 'Location']
        response = {'@odata.type': '#Session.v1_8_0.Session', '@odata.id': OWN, 'Id': 'owned'}
        if mode in ('inspur', 'inspur-public'):
            response = {'ok': 0, 'Id': TOKEN}
            headers = [('Location', '/redfish/v1/SessionService/Sessions/owned'), ('X-Auth-Token', TOKEN)]
        if mode == 'password-change':
            response['@Message.ExtendedInfo'] = [{'MessageId': 'Base.1.17.PasswordChangeRequired'}]
        self.reply(201, response, headers)

    def do_DELETE(self):
        auth = self.record()
        if self.path != ('/redfish/v1/SessionService/Sessions/owned' if self.server.mode in ('inspur', 'inspur-public') else OWN) or auth != 'token':
            self.reply(403)
            return
        self.server.active = False
        if self.server.mode == 'drop-logout':
            self.drop()
        elif self.server.mode == 'delete-204':
            self.reply(204)
        else:
            self.reply(200, {'@Message.ExtendedInfo': [{'MessageId': 'Base.1.17.Success'}]})


class Authentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='bcontrol-auth-')
        cls.root = Path(cls.temp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(cls.root / 'key.pem'), '-out', str(cls.root / 'cert.pem'),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.root / 'cert.pem', cls.root / 'key.pem')
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        cls.temp.cleanup()

    def run_case(self, mode, login='auto', behavior='roundtrip'):
        self.server.mode, self.server.calls, self.server.active = mode, [], False
        self.server.login_valid = False
        env = dict(os.environ, BC_BMC_USERNAME=USER, BC_BMC_PASSWORD=PASSWORD)
        run = subprocess.run([CLIENT, f'https://localhost:{self.server.server_port}', str(self.root / 'cert.pem'),
                              login, 'strict', behavior], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn(TOKEN, run.stdout + run.stderr)
        self.assertNotIn(PASSWORD, run.stdout + run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result['login_count'], 1)
        self.assertFalse(any(auth == 'mixed' or cookie for _, _, auth, cookie in self.server.calls))
        self.assertLessEqual(sum(method == 'POST' for method, *_ in self.server.calls), 1)
        self.assertLessEqual(sum(method == 'DELETE' for method, *_ in self.server.calls), 1)
        return result

    def test_session_discovery_and_own_logout(self):
        for mode in ('standard', 'service-null', 'delete-204', 'password-change', 'absolute-location'):
            with self.subTest(mode=mode):
                result = self.run_case(mode)
                self.assertEqual(result['login_status'], 'ok')
                self.assertEqual(result['mode'], 2)
                self.assertEqual(result['flags'], 2 | (8 if mode == 'password-change' else 0))
                self.assertEqual(result['read_http'], 200)
                self.assertEqual(result['logout_status'], 'ok')
                self.assertEqual(result['logout_flags'], 16)
                self.assertEqual(result['logout_count'], 1)
                self.assertEqual(result['post_logout_http'], 401)
                self.assertEqual(result['connection_state'], 2)
                self.assertFalse(result['endpoint_available'])
                self.assertEqual(result['session_uri'], OWN)
                self.assertTrue(self.server.login_valid)
                self.assertFalse(self.server.active)
                self.assertEqual(self.server.calls[0][2], 'none')
                self.assertEqual([path for method, path, *_ in self.server.calls if method == 'DELETE'], [OWN])

    def test_inspur_authentication_before_service_root(self):
        result = self.run_case('inspur', behavior='probe-login')
        self.assertEqual(result['login_status'], 'ok')
        self.assertEqual(result['flags'], 34)
        self.assertEqual((result['read_http'], result['post_logout_http'], result['logout_status']), (200, 401, 'ok'))
        self.assertFalse(any(auth == 'basic' for _, _, auth, _ in self.server.calls))
        self.assertEqual(sum(method == 'POST' for method, *_ in self.server.calls), 1)
        result = self.run_case('inspur-unknown')
        self.assertNotEqual(result['login_status'], 'ok')
        self.assertFalse(any(method == 'POST' for method, *_ in self.server.calls))

    def test_inspur_resource_compatibility_is_gated(self):
        self.assertTrue(self.run_case('inspur', behavior='resources')['resources_ok'])
        result = self.run_case('inspur-public', behavior='resources')
        self.assertTrue(result['resources_ok'])
        self.assertEqual(result['flags'], 34)
        self.assertEqual(sum(method == 'POST' for method, *_ in self.server.calls), 1)
        result = self.run_case('inspur-public-unknown')
        self.assertEqual(result['login_status'], 'ok')
        self.assertEqual(result['flags'], 2)
        self.assertFalse(self.run_case('absent', behavior='resources')['resources_ok'])

    def test_capability_absence_only_falls_back(self):
        for mode in ('absent', 'service-disabled', 'post-404', 'post-405', 'post-501'):
            with self.subTest(mode=mode):
                result = self.run_case(mode)
                self.assertEqual(result['login_status'], 'ok')
                self.assertEqual(result['mode'], 1)
                self.assertEqual(result['flags'], 1)
                self.assertEqual(result['read_http'], 200)
                self.assertEqual(result['logout_count'], 0)
        result = self.run_case('absent', login='session')
        self.assertEqual(result['login_status'], 'unsupported')
        self.assertFalse(any(auth == 'basic' for _, _, auth, _ in self.server.calls))
        result = self.run_case('basic-only', login='basic')
        self.assertEqual(result['login_status'], 'ok')
        self.assertEqual(result['flags'], 0)
        self.assertFalse(any(method == 'POST' for method, *_ in self.server.calls))

    def test_failures_do_not_fall_back_or_replay(self):
        for mode in ('post-401', 'post-403', 'post-429', 'post-500', 'service-401',
                     'missing-token', 'missing-location', 'foreign-location', 'wrong-port-location', 'drop-login'):
            with self.subTest(mode=mode):
                result = self.run_case(mode)
                self.assertNotEqual(result['login_status'], 'ok')
                self.assertFalse(result['flags'] & 1)
                self.assertFalse(any(auth == 'basic' for _, _, auth, _ in self.server.calls))
                self.assertEqual(result['logout_count'], 0)
                if mode in ('post-500', 'missing-token', 'missing-location', 'foreign-location', 'wrong-port-location', 'drop-login'):
                    self.assertTrue(result['flags'] & 4)

    def test_cancellation_and_lost_logout(self):
        result = self.run_case('standard', behavior='cancel-login')
        self.assertEqual(result['login_status'], 'cancelled')
        self.assertEqual(self.server.calls, [])
        result = self.run_case('standard', behavior='cancel-logout')
        self.assertEqual(result['logout_status'], 'outcome_unknown')
        self.assertEqual(result['post_logout_http'], 200)
        self.assertFalse(result['endpoint_available'])
        self.assertTrue(self.server.active)
        self.assertFalse(any(method == 'DELETE' for method, *_ in self.server.calls))
        result = self.run_case('drop-logout')
        self.assertEqual(result['logout_status'], 'outcome_unknown')
        self.assertEqual(result['post_logout_http'], 401)
        self.assertFalse(result['endpoint_available'])


if __name__ == '__main__':
    unittest.main()
