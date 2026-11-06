import http.server
import gzip
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

from inspur_fixture import PAGE, SCRIPT, SCRIPT_NEGOTIATED, VIEWER

CLIENT = str(Path(sys.argv.pop(1)).resolve())
USER, PASSWORD = 'probe-user', 'probe-password'
KEYBOARD = b'''this.m_USBKeyProcessor.setAutoKeybreakMode(!0);
this.m_USBKeyProcessor.convertKeyCode(this.keyCode,this.keyLocation,this.keyPress);
t.writeInt8(n),t.writeInt8(e?1:0),t.writeInt8Array(l);
this.autoKeybreakMode&&(i=!0);if(this.autoKeybreakMode)return null;'''
RPC_PAGE = b'<img src="img/inspur_logo.png"><script src="js/signin.js"></script><button ng-click="doValidate()"></button>'
RPC_SCRIPT = b'''url: '/rpc/WEBSES/create.asp'
data: "WEBVAR_USERNAME=" + UserName + "&" + "WEBVAR_PASSWORD=" + Password
WEBVAR_JSONVAR_WEB_SESSION.WEBVAR_STRUCTNAME_WEB_SESSION[0].SESSION_COOKIE
WEBVAR_JSONVAR_WEB_SESSION.WEBVAR_STRUCTNAME_WEB_SESSION[0].CSRFTOKEN
"SessionCookie=" + login_cookie
url: 'rpc/WEBSES/logout.asp'
top.location.href = "/main.html"
'''

def rpc_reply(name, payload):
    return b'// AMI RPC\n\n//Dynamic Data Begin\n' + name + b' = ' + payload + b';\n//Dynamic data end\n'



class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body, headers=(), short=False):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw) + (100 if short else 0)))
        if short:
            self.send_header('Connection', 'close')
            self.close_connection = True
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def form(self):
        length = int(self.headers.get('Content-Length', '0'))
        return urllib.parse.parse_qs(self.rfile.read(length).decode())

    def do_POST(self):
        self.server.paths.append(self.path)
        if self.path == '/rpc/WEBSES/create.asp' and self.server.mode.startswith('inspur-rpc'):
            assert self.form() == {'WEBVAR_USERNAME': [USER], 'WEBVAR_PASSWORD': [PASSWORD]}
            assert not self.headers.get('Cookie')
            origin = 'https://localhost:' + str(self.server.server_port)
            assert self.headers.get('Origin') == origin and self.headers.get('Referer') == origin + '/index.html'
            self.reply(200, rpc_reply(b'WEBVAR_JSONVAR_WEB_SESSION',
                b"{HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'legacy-cookie',CSRFTOKEN:'csrf-token'},{}]}"),
                short=True)
            return
        if self.path == '/api/session':
            form = self.form()
            if self.server.mode in ('legacy', 'body-cookie', 'bad-jnlp', 'language-only', 'missing-jnlp'):
                self.reply(404, {}); return
            if self.server.mode == 'inspur':
                assert form == {'username': ['PkckKJa45gW4xS3aUUSzYQ=='], 'password': ['QZ5uDTALT/eLYbEdZlfVIA=='], 'encrypt_flag': ['2'], 'login_tag': ['12345678']}
                form = {'username': [USER], 'password': [PASSWORD]}
            if self.server.mode == 'inspur-negotiated':
                assert form == {
                    'username': ['f-d-10-1d-1a-52-a-c-1a-d'],
                    'password': ['f-d-10-1d-1a-52-f-1e-c-c-8-10-d-1b'],
                    'encrypt_flag': ['1'], 'login_tag': ['12345678'],
                }
                form = {'username': [USER], 'password': [PASSWORD]}
            if form.get('username') == [USER] and form.get('password') == [PASSWORD]:
                self.reply(200, {'ok': True, 'CSRFToken': 'csrf-token'},
                           [('Set-Cookie', 'QSESSIONID=session-value; Path=/; HttpOnly')])
            else:
                self.reply(401, {'ok': False})
            return
        if self.path == '/rpc/WEBSES/create.asp' and self.server.mode in ('legacy', 'body-cookie', 'nec', 'bad-jnlp', 'language-only', 'missing-jnlp'):
            form = self.form()
            if form.get('WEBVAR_USERNAME') == [USER] and form.get('WEBVAR_PASSWORD') == [PASSWORD]:
                if self.server.mode == 'language-only':
                    self.reply(200, {'ok': True}, [('Set-Cookie', 'lang=EN; Path=/')]); return
                if self.server.mode == 'nec':
                    assert form.get('WEBVAR_TYPE') == ['Https'] and len(form.get('WEBVAR_IPADDR', [''])[0]) == 8
                    self.reply(200, b"var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:0, WEBVAR_STRUCTNAME_WEB_SESSION:[{'SESSION_COOKIE':'legacy-cookie'},{}]};")
                else:
                    self.reply(200, b"{'SESSION_COOKIE' : 'legacy-cookie'}",
                               [('Set-Cookie', 'SessionCookie=legacy-cookie; Path=/')] if self.server.mode == 'legacy' else [])
            else:
                self.reply(401, b'')
            return
        if self.path == '/rpc/getcsrftoken.asp' and self.server.mode == 'nec':
            assert 'SessionCookie=legacy-cookie' in self.headers.get('Cookie', '')
            assert self.form().get('SESSION_COOKIE') == ['legacy-cookie']
            self.reply(200, b"var WEBVAR_JSONVAR_GETCSRFTOKEN = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_GETCSRFTOKEN:[{CSRFTOKEN:'csrf-token'},{}]};"); return
        self.reply(404, {})

    def do_DELETE(self):
        assert self.path == '/api/session' and self.headers.get('X-CSRFTOKEN') == 'csrf-token'
        self.server.logouts += 1
        self.reply(204, b'')

    def do_GET(self):
        self.server.paths.append(self.path)
        assert self.headers.get('User-Agent', '').startswith('bControl/0.1')
        if self.server.mode.startswith('inspur-rpc'):
            if self.path == '/index.html':
                self.reply(200, RPC_PAGE, [('Set-Cookie', 'test=1; Path=/')]); return
            if self.path == '/js/signin.js':
                self.reply(200, b'' if self.server.mode.endswith('unknown') else RPC_SCRIPT); return
            if self.path == '/rpc/WEBSES/logout.asp':
                assert self.headers.get('Cookie') == 'SessionCookie=legacy-cookie'
                assert self.headers.get('X-CSRFTOKEN') == 'csrf-token'
                self.server.logouts += 1
                self.reply(200, rpc_reply(b'WEBVAR_JSONVAR_WEB_SESSION_LOGOUT', b'{HAPI_STATUS:0}'), short=True); return
            if self.path.startswith('/Java/jviewer.jnlp'):
                assert self.path == '/Java/jviewer.jnlp?EXTRNIP=' + self.server.expected_host + '&JNLPSTR=JViewer'
                assert self.headers.get('Cookie') == 'SessionCookie=legacy-cookie'
                jnlp = (b'<jnlp><application-desc><argument>-hostname</argument><argument>192.0.2.50</argument>'
                        b'<argument>-kvmport</argument><argument>7582</argument>'
                        b'<argument>-kvmsecure</argument><argument>0</argument>'
                        b'<argument>-kvmtoken</argument><argument>legacy-token</argument>'
                        b'</application-desc></jnlp>')
                self.reply(200, jnlp[:-7] if self.server.mode.endswith('truncated') else jnlp, short=True); return
        if self.server.mode.startswith('split'):
            resources = {'/viewer.min.js': VIEWER + KEYBOARD if self.server.mode != 'split-unknown' else VIEWER.replace(b'VIDEO_PACKET_SIZE:373', b'VIDEO_PACKET_SIZE:438'),
                         '/api/kvm/token': {'token': 'h5-token', 'session': 'h5-session', 'client_ip': '192.0.2.2'},
                         '/api/settings/media/adviser': {'status': 1, 'singleport_status': 1},
                         '/api/settings/media/instance': {'cd_status': 1, 'single_port_enabled': 1, 'num_cd': 1, 'kvm_num_cd': 24}}
            if self.path == '/api/settings/media/h5viewercfg' and self.server.mode == 'split-denied':
                self.reply(403, {}); return
            if self.path in resources:
                if self.path != '/viewer.min.js':
                    assert self.headers.get('X-CSRFTOKEN') == 'csrf-token'
                    assert 'QSESSIONID=session-value' in self.headers.get('Cookie', '')
                self.reply(200, resources[self.path]); return
        if self.server.mode in ('inspur', 'inspur-negotiated'):
            negotiated = self.server.mode == 'inspur-negotiated'
            resources = {'/index.html': PAGE, '/js/signin.js': SCRIPT_NEGOTIATED if negotiated else SCRIPT,
                         '/viewer.min.js': VIEWER + (KEYBOARD.replace(b't.write', b'u.write') +
                             b'"WEB_APP_PROXY";9999==this.port?new WebSocket' if negotiated else b''),
                         '/api/randomtag': {'random': 12345678, **({'encrypt_ctrl': 1} if negotiated else {})},
                         '/api/kvm/token': {'token': 'h5-token', 'session': 'h5-session', 'client_ip': '192.0.2.2'},
                         '/api/settings/media/adviser': {'status': 1, 'singleport_status': int(not negotiated)},
                         '/api/settings/media/instance': {'cd_status': 1, 'single_port_enabled': int(not negotiated), 'num_cd': 4, 'kvm_num_cd': 2}}
            if self.path in resources:
                self.reply(200, resources[self.path]); return
        if self.path == '/index.html' and self.server.mode in ('nec', 'h5-misleading'):
            self.reply(200, gzip.compress(b'<title>EXPRESSSCOPE Engine 3</title>'), [('Content-Encoding','gzip')]); return
        if self.path == '/rpc/WEBSES/logout.asp':
            assert 'SessionCookie=legacy-cookie' in self.headers.get('Cookie', '')
            self.server.logouts += 1
            self.reply(200, b'var reply = {HAPI_STATUS:0};'); return
        if self.path == '/viewer.min.js' and self.server.mode == 'h5-keyboard':
            self.reply(200, KEYBOARD); return
        if self.path == '/api/settings/media/h5viewercfg' and self.server.mode in ('h5', 'h5-misleading', 'h5-keyboard'):
            if 'QSESSIONID=session-value' in self.headers.get('Cookie', '') and self.headers.get('X-CSRFTOKEN') == 'csrf-token':
                self.reply(200, {'token': 'h5-token', 'session': 'h5-session',
                                 'client_ip': '192.0.2.10', 'server_ip': '192.0.2.1'})
            else:
                self.reply(401, {'error': 'session'})
            return
        if self.path.startswith('/Java/jviewer.jnlp') and self.server.mode in ('legacy', 'body-cookie', 'nec', 'bad-jnlp', 'language-only', 'missing-jnlp'):
            if 'SessionCookie=legacy-cookie' not in self.headers.get('Cookie', ''):
                self.reply(401, {})
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
            if self.server.mode in ('nec', 'body-cookie'):
                assert query.get('ext_ip') == [self.server.expected_host]
            if self.server.mode == 'legacy':
                assert query == {'EXTRNIP': [self.server.expected_host], 'JNLPSTR': ['JViewer'], 'ext_ip': [self.server.expected_host]}
            if self.server.mode == 'missing-jnlp':
                self.reply(404, {}); return
            if self.server.mode == 'bad-jnlp':
                self.reply(200, b'<html>not a viewer</html>'); return
            jnlp = ('<jnlp><application-desc main-class="com.ami.kvm.jviewer.JViewer">'
                    '<argument>-hostname</argument><argument>192.0.2.50</argument>'
                    '<argument>-kvmport</argument><argument>7582</argument>'
                    '<argument>-kvmsecure</argument><argument>1</argument>'
                    '<argument>-kvmtoken</argument><argument>legacy-token</argument>'
                    '<argument>-kvmtokentype</argument><argument>0</argument>'
                    '<argument>-vmsecure</argument><argument>0</argument>'
                    '<argument>-cdport</argument><argument>6200</argument>'
                    '<argument>-singleportenabled</argument><argument>0</argument>'
                    '<argument>-cdnum</argument><argument>1</argument>'
                    '</application-desc></jnlp>')
            self.reply(200, jnlp.encode())
            return
        self.reply(404, {})


class Probe(unittest.TestCase):
    def run_client(self, mode, password=PASSWORD, profile=None, host="192.0.2.1"):
        with tempfile.TemporaryDirectory(prefix='bcontrol-probe-') as directory:
            root = Path(directory)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key'),
                            '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.mode = mode
            server.expected_host = host
            server.logouts = 0
            server.paths = []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'cert', root / 'key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            try:
                command = [CLIENT, 'https://localhost:' + str(server.server_port), str(root / 'cert'),
                           USER, password, host]
                if profile is not None:
                    command.append(profile)
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                if profile is not None and profile != 'inspur-rpc':
                    self.assertNotIn('/index.html', server.paths)
                if profile in ('login-nec', 'login-basic'):
                    self.assertNotIn('/api/session', server.paths)
                    self.assertEqual(server.paths.count('/rpc/WEBSES/create.asp'), 1)
                if mode in ('split-unknown', 'split-denied') or (mode == 'split' and profile == '438'):
                    self.assertNotIn('/api/kvm/token', server.paths)
                if mode == 'split-denied' or (mode == 'split' and profile == '438'):
                    self.assertNotIn('/viewer.min.js', server.paths)
                launches = [path for path in server.paths if path.startswith('/Java/jviewer.jnlp')]
                self.assertLessEqual(len(launches), 1, server.paths)
                if password == PASSWORD:
                    self.assertEqual(server.logouts, 0 if mode in ('language-only', 'inspur-rpc-unknown') else 1,
                                     result.stdout + result.stderr)
                if mode == 'inspur-rpc-unknown':
                    self.assertNotIn('/rpc/WEBSES/create.asp', server.paths)
                return result
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_inspur_encrypted_login_and_split_config(self):
        for mode in ('inspur', 'inspur-negotiated'):
            with self.subTest(mode=mode):
                result = self.run_client(mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual((row['profile_variant'], row['wire_kind'], row['logout']), (4, 4, 'ok'))
                self.assertEqual(row['server_ip'], '')
                self.assertEqual((row['media_status'], row['media_devices']), ('ok', 2))
                self.assertEqual(row['keyboard_mode'], 2 if mode == 'inspur-negotiated' else 0)

    def test_inspur_rpc_accepts_complete_jnlp_only(self):
        for mode, expected in [('inspur-rpc', 'ok'), ('inspur-rpc-truncated', 'protocol_error'),
                               ('inspur-rpc-unknown', 'unsupported')]:
            with self.subTest(mode=mode):
                result = self.run_client(mode, profile='inspur-rpc')
                self.assertEqual(json.loads(result.stdout)['status'], expected, result.stderr)

    def test_split_h5_plain_login_and_media_gate(self):
        for profile in (None, 'auto', '373', 'login-h5'):
            result = self.run_client('split', profile=profile)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual((row['profile_variant'], row['wire_kind'], row['logout']), (4, 4, 'ok'))
            self.assertEqual(row['media_status'], 'unsupported')
            self.assertEqual(row['keyboard_mode'], 2)
        for mode, profile in [('split-unknown', None), ('split-denied', None), ('split', '438')]:
            result = self.run_client(mode, profile=profile)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_h5_keyboard_evidence_is_independent_of_auth_layout(self):
        result = self.run_client('h5-keyboard')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row = json.loads(result.stdout)
        self.assertEqual((row['wire_kind'], row['keyboard_mode']), (2, 2))

    def test_h5_and_legacy_detection(self):
        result = self.run_client('h5')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        row = json.loads(result.stdout)
        self.assertEqual((row['status'], row['kind'], row['http_status']), ('ok', 1, 200))
        self.assertEqual((row['token'], row['server_ip']), ('h5-token', '192.0.2.1'))
        self.assertGreater(row['cookie_length'], 0)
        self.assertEqual(row['profile_variant'], 1)
        self.assertEqual(row['keyboard_mode'], 0)
        self.assertFalse(row['profile_verified'])
        result = self.run_client('legacy')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        row = json.loads(result.stdout)
        self.assertEqual((row['status'], row['kind']), ('ok', 2))
        self.assertEqual((row['host'], row['token'], row['port'], row['secure']), ('192.0.2.50', 'legacy-token', 7582, 1))
        self.assertEqual(row['profile_variant'], 0)
        self.assertGreater(row['cookie_length'], 0)
        for mode in ('nec', 'body-cookie'):
            result = self.run_client(mode)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['logout'], 'ok')
        for mode, expected in [('bad-h5-config', 'http_error'), ('bad-jnlp', 'protocol_error'), ('language-only', 'protocol_error'), ('missing-jnlp', 'http_error')]:
            result = self.run_client(mode)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['status'], expected)
            if mode == 'language-only':
                row = json.loads(result.stdout)
                self.assertEqual((row['failure_phase'], row['failure_cause']), (2, 5))
        result = self.run_client('h5', password='wrong')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'authentication_failed')
        row = json.loads(result.stdout)
        self.assertEqual((row['failure_phase'], row['failure_cause']), (2, 8))

    def test_structured_discovery_and_explicit_legacy_variant(self):
        result = self.run_client('h5-misleading', profile='auto')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['profile_variant'], 1)
        result = self.run_client('legacy', profile='auto')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row = json.loads(result.stdout)
        self.assertEqual((row['profile_variant'], row['wire_kind']), (0, 0))
        result = self.run_client('nec', profile='195')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row = json.loads(result.stdout)
        self.assertEqual((row['profile_variant'], row['wire_kind']), (3, 3))


    def test_combined_query_preserves_both_encoded_host_values(self):
        for host in ['2001:db8::1%en0', '.'.join(['a' * 63] * 3 + ['a' * 61])]:
            result = self.run_client('legacy', profile='auto', host=host)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual((row['profile_variant'], row['wire_kind']), (0, 0))

    def test_explicit_login_does_not_select_console_layout(self):
        for mode, contract in [('nec', 'login-nec'), ('legacy', 'login-basic')]:
            result = self.run_client(mode, profile=contract)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual((row['profile_variant'], row['wire_kind']), (0, 0))
            self.assertEqual(row['logout'], 'ok')
        result = self.run_client('nec', password='wrong', profile='login-nec')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'authentication_failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
