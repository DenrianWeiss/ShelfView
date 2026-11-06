"""Exercise source-proven Web login and same-owner startup with synthetic resources."""
import argparse
import ast
import importlib.util
import io
import json
import zipfile
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-build', type=Path, required=True)
    parser.add_argument('--default', action='store_true')
    parser.add_argument('--redfish', choices=['success', 'login-fails', 'metadata-fails', 'malformed', 'conflict', 'unsupported-profile', 'logout-fails'])
    parser.add_argument('--swift-scratch', type=Path, default=Path('build-apple'))
    parser.add_argument('--mode', choices=['phase1', 'native', 'unknown-jar', 'invalid-jar', 'jar-http-error', 'artifact-start-failure', 'unknown-route', 'rejected', 'invalid-public', 'cancel'], default='native')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location('reference', root / 'tests/redfish_integration.py')
    reference = importlib.util.module_from_spec(spec)
    sys.argv = ['reference', str(args.c_build.resolve() / 'bcontrol-redfish-client')]
    spec.loader.exec_module(reference)
    source = (root / 'tests/web_login_test.c').read_text()
    def literal(name):
        match = re.search(r'static const char ' + name + r'\[\]\s*=\s*((?:"(?:\\.|[^"\\])*"\s*)+);', source)
        if not match:
            raise RuntimeError('Missing synthetic source model: ' + name)
        return ''.join(ast.literal_eval(part) for part in re.findall(r'"(?:\\.|[^"\\])*"', match[1]))
    login_source = literal('script').split('function finished')[0] + literal('response_model')
    jar = subprocess.run([str(args.c_build.resolve() / 'bcontrol-megarac-class-test'), '--emit-jar'],
                         check=True, capture_output=True).stdout
    if args.mode == 'unknown-jar':
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as resource:
            resource.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\n\r\n')
            resource.writestr('notes.txt', 'fixture-asset-marker')
        jar = archive.getvalue()
    elif args.mode == 'invalid-jar':
        jar = b'<html>fixture-sensitive-jar</html>'
    native = socket.socket()
    native.bind(('127.0.0.1', 0)); native.listen(1); native.settimeout(20)
    native_connections = []
    def close_peer():
        try:
            peer, _ = native.accept(); native_connections.append(1); peer.close()
        except OSError:
            pass
    threading.Thread(target=close_peer, daemon=True).start()
    pages = {
        '/': "<script src='index.js'></script><iframe src='page/login.html'></iframe>",
        '/index.js': "var keySessionCookie='SessionCookie';" if args.mode != 'invalid-public' else "var unrelated='SessionCookie';",
        '/page/login.html': "<script src='../lib/xmit.js'></script><script src='../js/login.js'></script><input type=text id=login_username><input type=password id=login_password>",
        '/lib/xmit.js': literal('xmit'), '/js/login.js': login_source,
        '/page/top.html': "<iframe src='menu/remote.html'></iframe>",
        '/page/menu/remote.html': "<script src='../../js/menu.js'></script>",
        '/js/menu.js': "function menu(){var html=\"<a href='../contents/remote/operation.html'>remote</a>\";$('#menu').replaceWith(html);}",
        '/page/contents/remote/operation.html': "<script src='../../../js/license.js'></script>",
        '/js/license.js': "function execute(){window.open('jviewer_launch.html','RemoteConsole','width=600');}",
        '/page/contents/remote/jviewer_launch.html': "<script src='../../../js/jviewer_launch.js'></script>",
        '/js/jviewer_launch.js': "window.location='/Java/jviewer.jnlp?ext_ip=localhost';" if args.mode != 'unknown-route' else "window.location=dynamic;",
    }
    login = '/rpc/WEBSES/create.asp'
    csrf = '/rpc/getcsrftoken.asp'
    logout = '/rpc/WEBSES/logout.asp'
    jnlp_path = '/Java/jviewer.jnlp?ext_ip=localhost'
    sessions = '/redfish/v1/SessionService/Sessions'
    owned = sessions + '/fixture'
    manager = '/redfish/v1/Managers/node'
    redfish_pages = {
        '/redfish/v1/': {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot', 'RedfishVersion': '1.17.0',
            'SessionService': {'@odata.id': '/redfish/v1/SessionService'},
            'Managers': {'@odata.id': '/redfish/v1/Managers'}},
        '/redfish/v1/SessionService': {'@odata.type': '#SessionService.v1_1_0.SessionService', 'ServiceEnabled': True, 'Sessions': {'@odata.id': sessions}},
        '/redfish/v1/Managers': {'@odata.type': '#ManagerCollection.ManagerCollection', 'Members': [{'@odata.id': manager}]},
        manager: {'@odata.id': manager, 'Manufacturer': 'Unadapted fixture brand'},
        manager + '/Attributes': {'@odata.type': '#DellAttributes.v1_0_0.DellAttributes',
            'Attributes': {'VirtualConsole.1.PluginType': 'eHTML5'}},
    }
    if args.redfish in ('conflict', 'unsupported-profile'):
        redfish_pages[manager]['Attributes'] = {'@odata.id': manager + '/Attributes'}
        if args.redfish == 'conflict':
            redfish_pages['/redfish/v1/']['Oem'] = {'Hpe': {'Manager': [{'ManagerType': 'iLO 5'}]}}
        else:
            redfish_pages[manager + '/Attributes']['Attributes']['VirtualConsole.1.PluginType'] = 'Unknown'
    if args.redfish == 'malformed':
        redfish_pages[manager]['Attributes'] = 42
    def authenticated(handler):
        return 'SessionCookie=web-fixture' in handler.headers.get('Cookie', '')
    def get(handler):
        handler.server.events.append(('GET', handler.path))
        if args.redfish and handler.path.startswith('/redfish/'):
            if handler.path.startswith('/redfish/v1/Managers') and handler.headers.get('X-Auth-Token') != 'redfish-fixture':
                raise RuntimeError('Metadata must use the Redfish owner')
            if handler.path == manager and args.redfish == 'metadata-fails':
                return handler.reply(500, {})
            body = redfish_pages.get(handler.path)
            return handler.reply(200 if body is not None else 404, body or {})
        if args.redfish and ('DELETE', owned) not in handler.server.events:
            raise RuntimeError('Web discovery began before Redfish logout')
        if handler.headers.get('X-Auth-Token') or handler.headers.get('Authorization'):
            raise RuntimeError('Redfish authentication crossed into Web discovery')
        if handler.path in ('/', '/index.js', '/page/login.html', '/lib/xmit.js', '/js/login.js'):
            if any(handler.headers.get(h) for h in ('Authorization', 'X-Auth-Token', 'Cookie')):
                raise RuntimeError('Public source discovery inherited authentication')
        elif not authenticated(handler):
            return handler.reply(405, b'')
        if handler.path == logout:
            return handler.reply(200, b'var response={HAPI_STATUS:0};')
        if handler.path == jnlp_path:
            xml = ('<jnlp><resources><jar href="viewer.jar" main="true"/></resources><application-desc>'
                '<argument>-hostname</argument><argument>localhost</argument><argument>-kvmtoken</argument><argument>fixture-token</argument>'
                '<argument>-kvmport</argument><argument>' + str(native.getsockname()[1]) + '</argument>'
                '<argument>-kvmsecure</argument><argument>0</argument></application-desc></jnlp>')
            if args.mode == 'artifact-start-failure':
                xml = xml.replace('href="viewer.jar"', 'href="https://untrusted.invalid/viewer.jar"')
            return handler.reply(200, xml.encode())
        if handler.path == '/Java/viewer.jar':
            return handler.reply(404 if args.mode == 'jar-http-error' else 200, jar)
        body = pages.get(handler.path)
        handler.reply(200 if body is not None else 404, body.encode() if body is not None else b'')
    def post(handler):
        raw = handler.rfile.read(int(handler.headers.get('Content-Length', '0'))).decode()
        handler.server.events.append(('POST', handler.path))
        if args.redfish and handler.path == sessions:
            if json.loads(raw) != {'UserName': 'user', 'Password': 'test-secret'}:
                raise RuntimeError('Unexpected Redfish credentials')
            if args.redfish == 'login-fails':
                return handler.reply(401, {})
            return handler.reply(201, {'@odata.type': '#Session.v1_0_0.Session', '@odata.id': owned},
                [('X-Auth-Token', 'redfish-fixture'), ('Location', owned)])
        if args.redfish and (args.redfish != 'success' or ('DELETE', owned) not in handler.server.events):
            raise RuntimeError('Unexpected Web authentication')
        if handler.headers.get('X-Auth-Token') or handler.headers.get('Authorization'):
            raise RuntimeError('Redfish authentication crossed into Web login')
        body = urllib.parse.parse_qs(raw)
        if handler.path == login:
            if body.get('WEBVAR_USERNAME') != ['user'] or body.get('WEBVAR_PASSWORD') != ['test-secret']:
                raise RuntimeError('Unexpected fixture credentials')
            if not re.fullmatch(r'\d{8}', body.get('WEBVAR_IPADDR', [''])[0]) or body.get('WEBVAR_TYPE') != ['Https']:
                raise RuntimeError('Source-proven request shape changed')
            if args.mode == 'cancel':
                time.sleep(0.4)
            payload = b'var WEBVAR_JSONVAR_WEB_SESSION={HAPI_STATUS:-2};' if args.mode == 'rejected' else b"var WEBVAR_JSONVAR_WEB_SESSION={HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'web-fixture'}]};"
            return handler.reply(200, payload)
        if handler.path == csrf and authenticated(handler) and body == {'SESSION_COOKIE': ['web-fixture']}:
            return handler.reply(200, b"var WEBVAR_JSONVAR_GETCSRFTOKEN={HAPI_STATUS:0,WEBVAR_STRUCTNAME_GETCSRFTOKEN:[{CSRFTOKEN:'csrf-fixture'}]};")
        raise RuntimeError('Unproven POST or missing owner')
    def delete(handler):
        handler.server.events.append(('DELETE', handler.path))
        if handler.path != owned or handler.headers.get('X-Auth-Token') != 'redfish-fixture':
            raise RuntimeError('Unexpected Redfish session cleanup')
        handler.reply(500 if args.redfish == 'logout-fails' else 204, {})
    reference.Handler.do_GET, reference.Handler.do_POST, reference.Handler.do_DELETE = get, post, delete
    reference.Redfish.setUpClass()
    try:
        with reference.Redfish().fixture() as server:
            server.events = []
            environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
            environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'), BC_TEST_OWNED_WEB_MODE=args.mode)
            if args.default:
                environment['BC_TEST_CONSOLE_DEFAULT'] = '1'
            build = str(args.c_build.resolve())
            if args.redfish:
                subprocess.run([str(args.c_build.resolve() / 'bcontrol-console-prepare-client'),
                    environment['BC_TEST_REDFISH_URL'], environment['BC_TEST_REDFISH_CA'],
                    'success' if args.redfish == 'success' else 'failure'], check=True, timeout=20)
                mutations = [event for event in server.events if event[0] != 'GET']
                expected = [('POST', sessions)]
                if args.redfish != 'login-fails':
                    expected.append(('DELETE', owned))
                if args.redfish == 'success':
                    expected += [('POST', login), ('POST', csrf)]
                if mutations != expected:
                    raise RuntimeError('Unexpected owner transition: ' + repr(server.events))
                if args.redfish != 'login-fails' and ('GET', manager) not in server.events:
                    raise RuntimeError('Fixture did not reach Manager metadata')
                if args.redfish in ('conflict', 'unsupported-profile') and ('GET', manager + '/Attributes') not in server.events:
                    raise RuntimeError('Fixture did not inspect the protocol candidate')
                if args.redfish != 'success':
                    if any(path in pages or path in (jnlp_path, '/Java/viewer.jar') for _, path in server.events):
                        raise RuntimeError('Failed Redfish discovery fell back to Web')
                    print('Redfish fallback gate passed:', args.redfish)
                    return
            else:
                subprocess.run(['swift', 'test', '--package-path', str(root / 'frontends/apple'),
                    '--scratch-path', str(args.swift_scratch.resolve()), '-Xcc', '-I', '-Xcc', str(root / 'include'),
                    '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'), '-Xlinker', '-L', '-Xlinker', build,
                    '-Xlinker', '-rpath', '-Xlinker', build, '--filter',
                    'testFixtureOwnedWebLoginAndCleanup' if args.mode in ('phase1', 'cancel') else 'testFixtureOwnedWebDiscoveryDrivesActualMegaRACBackend'],
                    cwd=root, env=environment, check=True, timeout=120)
            expected_login = 0 if args.mode == 'invalid-public' else 1
            expected_logout = 0 if args.mode in ('invalid-public', 'rejected') else 1
            expected_csrf = 0 if args.mode in ('invalid-public', 'rejected', 'cancel') else 1
            for event, expected in [(('POST', login), expected_login), (('POST', csrf), expected_csrf), (('GET', logout), expected_logout),
                                    (('GET', jnlp_path), int(args.mode in ('native', 'unknown-jar', 'invalid-jar', 'jar-http-error', 'artifact-start-failure'))), (('GET', '/Java/viewer.jar'), int(args.mode in ('native', 'unknown-jar', 'invalid-jar', 'jar-http-error')))]:
                if server.events.count(event) != expected:
                    raise RuntimeError('Unexpected source/owner request count for ' + repr(event) + ': ' + repr(server.events))
            if native_connections != ([1] if args.mode == 'native' and not args.redfish else []):
                raise RuntimeError('Unproven native connection or missing actual backend')
            print('Owned Web source/owner fixture passed:', args.mode)
    finally:
        native.close()
        reference.Redfish.tearDownClass()


if __name__ == '__main__':
    main()
