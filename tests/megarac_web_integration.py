"""MegaRAC bundle discovery, Redfish handoff and H5 layout selection."""
import gzip
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

from inspur_fixture import VIEWER

CLIENT = str(Path(sys.argv.pop(1)).resolve())
PAGE = b'<main role="main" id="main"></main><script src="/source.min.js"></script>'
SCRIPT = b'''define("text!templates/login.html",[],function(){return '<input id="userid"><input id="password">'});
define("views/LoginView",["jquery","underscore","backbone","app"],function($){
function login(){$.ajax({type:"POST",url:"/api/session",dataType:"json",data:{username:$("#userid").val(),password:$("#password").val()},success:function(reply){
if(reply.passwordStatus){}else if(0===reply.ok){$.ajaxSetup({headers:{"X-CSRFTOKEN":reply.CSRFToken}});}}});}
function logout(){$.ajax({url:"/api/session",type:"DELETE"});}});'''
H5 = VIEWER.replace(b'/api/kvm/token', b'/api/settings/media/h5viewercfg') + b'''
var packet=new DataStream(K.VIDEO_PACKET_SIZE+K.CLINET_OWN_IP_LENGTH);
packet.writeCString(this.server_ip,K.CLINET_OWN_IP_LENGTH);'''


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body, headers=()):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.events.append(('GET', self.path))
        pages = {
            '/redfish/v1/': {'@odata.type': '#ServiceRoot.v1_6_0.ServiceRoot', 'RedfishVersion': '1.6.0', 'Managers': {'@odata.id': '/redfish/v1/Managers'},
                            'SessionService': {'@odata.id': '/redfish/v1/SessionService'}},
            '/redfish/v1/SessionService': {'@odata.type': '#SessionService.v1_1_0.SessionService', 'ServiceEnabled': True,
                                         'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}},
            '/redfish/v1/Managers': {'@odata.type': '#ManagerCollection.ManagerCollection',
                                   'Members': [{'@odata.id': '/redfish/v1/Managers/Self'}]},
            '/redfish/v1/Managers/Self': {'@odata.id': '/redfish/v1/Managers/Self',
                                        '@odata.type': '#Manager.v1_0_0.Manager', 'Manufacturer': 'Unbranded MegaRAC fixture'},
        }
        if self.path in pages:
            return self.reply(200, pages[self.path])
        if self.path == '/':
            page = self.server.page
            if self.server.mode == 'unrelated-page':
                page = b'<script src="/source.min.js"></script>'
            return self.reply(200, page)
        if self.path == '/source.min.js':
            source = self.server.source
            if self.server.mode == 'unknown-login':
                source = source.replace(b'password:$("#password").val()', b'password:hash($("#password").val())')
            if self.server.mode == 'ambiguous-login':
                source += SCRIPT
            if self.server.mode == 'over-budget':
                source += b' ' * (8 * 1024 * 1024)
            return self.reply(200, gzip.compress(source), [('Content-Encoding', 'gzip')])
        if self.path == '/api/settings/media/h5viewercfg':
            if self.headers.get('X-CSRFTOKEN') != 'fixture-csrf' or 'QSESSIONID=fixture' not in self.headers.get('Cookie', ''):
                return self.reply(401, {})
            return self.reply(200, {'token': 'fixture-token', 'session': 'fixture-session',
                                    'client_ip': '192.0.2.2', 'server_ip': '192.0.2.1'})
        if self.path == '/viewer.min.js':
            return self.reply(200, self.server.viewer)
        return self.reply(404, {})

    def do_POST(self):
        self.server.events.append(('POST', self.path))
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path == '/redfish/v1/SessionService/Sessions':
            return self.reply(201, {'@odata.type': '#Session.v1_0_0.Session', '@odata.id': self.path + '/owned'},
                              [('X-Auth-Token', 'redfish-token'), ('Location', self.path + '/owned')])
        if self.path == '/api/session':
            if urllib.parse.parse_qs(body.decode()) != {'username': ['user'], 'password': ['test-secret']}:
                return self.reply(401, {})
            return self.reply(200, {'ok': 0, 'CSRFToken': 'fixture-csrf'},
                              [('Set-Cookie', 'QSESSIONID=fixture; Path=/; Secure; HttpOnly')])
        return self.reply(404, {})

    def do_DELETE(self):
        self.server.events.append(('DELETE', self.path))
        return self.reply(204, b'')


class WebDiscovery(unittest.TestCase):
    def run_case(self, mode, assets=None):
        with tempfile.TemporaryDirectory(prefix='bcontrol-megarac-web-') as directory:
            root = Path(directory)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key'),
                            '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.mode, server.events = mode, []
            server.page, server.source, server.viewer = PAGE, SCRIPT + b' ' * 6832804, H5
            if assets:
                server.page, server.source, server.viewer = [(assets / name).read_bytes()
                    for name in ('index.html', 'source.min.js', 'viewer.min.js')]
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'cert', root / 'key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            try:
                success = mode == 'success'
                result = subprocess.run([CLIENT, 'https://localhost:' + str(server.server_port), str(root / 'cert'),
                    'h5' if success else 'failure'], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr + repr(server.events))
                expected_status = 0 if success else 8 if mode == 'over-budget' else 4
                self.assertIn(f'prepare status={expected_status} ', result.stderr)
                events = server.events
                self.assertIn(('DELETE', '/redfish/v1/SessionService/Sessions/owned'), events)
                self.assertEqual(events.count(('POST', '/api/session')), int(success), events)
                self.assertEqual(events.count(('DELETE', '/api/session')), int(success), events)
                self.assertNotIn(('POST', '/rpc/WEBSES/create.asp'), events)
                if success:
                    self.assertLess(events.index(('DELETE', '/redfish/v1/SessionService/Sessions/owned')),
                                    events.index(('POST', '/api/session')))
                    self.assertIn(('GET', '/viewer.min.js'), events)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_large_bundle(self):
        self.run_case('success')

    def test_unknown_login(self):
        self.run_case('unknown-login')

    def test_page_binding(self):
        self.run_case('unrelated-page')

    def test_ambiguous_login(self):
        self.run_case('ambiguous-login')

    def test_total_budget(self):
        self.run_case('over-budget')

    @unittest.skipUnless(os.environ.get('BC_TEST_MEGARAC_WEB_ASSETS'), 'optional extracted firmware assets')
    def test_firmware_assets(self):
        self.run_case('success', Path(os.environ['BC_TEST_MEGARAC_WEB_ASSETS']))


if __name__ == '__main__':
    unittest.main()
