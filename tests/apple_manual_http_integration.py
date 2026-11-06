"""Unknown default discovery permits one explicit HTTP contract; no login enumeration."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-build', type=Path, required=True)
    parser.add_argument('--swift-scratch', type=Path, default=Path('build-apple'))
    parser.add_argument('--mode', choices=['html5', 'rejected', 'cancel-choice', 'hard-denied'], default='html5')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location('reference', root / 'tests/redfish_integration.py')
    reference = importlib.util.module_from_spec(spec)
    sys.argv = ['reference', str(args.c_build.resolve() / 'bcontrol-redfish-client')]
    spec.loader.exec_module(reference)
    def get(handler):
        handler.server.events.append(('GET', handler.path))
        if handler.path == '/redfish/v1/':
            return handler.reply(401 if args.mode == 'hard-denied' else 404, {})
        if handler.path == '/':
            if handler.headers.get('Cookie') or handler.headers.get('Authorization'):
                raise RuntimeError('Unknown discovery must remain anonymous')
            return handler.reply(200, b'<html>Management</html>')
        if handler.path == '/api/settings/media/h5viewercfg':
            if 'QSESSIONID=fixture-session' not in handler.headers.get('Cookie', '') or handler.headers.get('X-CSRFTOKEN') != 'fixture-csrf':
                raise RuntimeError('H5 configuration requires its own session')
            return handler.reply(200, {'token': 'fixture-token', 'session': 'fixture-key',
                'client_ip': '127.0.0.1', 'server_ip': '127.0.0.1'})
        if handler.path == '/kvm':
            return handler.reply(400, {})
        raise RuntimeError('Unselected login or guessed resource: ' + handler.path)
    def post(handler):
        handler.server.events.append(('POST', handler.path))
        if handler.path != '/api/session':
            raise RuntimeError('Only the selected H5 login is authorized')
        body = urllib.parse.parse_qs(handler.rfile.read(int(handler.headers.get('Content-Length', '0'))).decode())
        if body != {'username': ['user'], 'password': ['test-secret']}:
            raise RuntimeError('Unexpected H5 contract shape')
        if args.mode == 'rejected':
            return handler.reply(401, {})
        handler.reply(200, {'CSRFToken': 'fixture-csrf'}, [('Set-Cookie', 'QSESSIONID=fixture-session; Path=/; HttpOnly')])
    def delete(handler):
        handler.server.events.append(('DELETE', handler.path))
        if handler.path != '/api/session' or handler.headers.get('X-CSRFTOKEN') != 'fixture-csrf':
            raise RuntimeError('Only the owned H5 session may be removed')
        handler.reply(200, {})
    reference.Handler.do_GET, reference.Handler.do_POST, reference.Handler.do_DELETE = get, post, delete
    reference.Redfish.setUpClass()
    try:
        with reference.Redfish().fixture() as server:
            server.events = []
            environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
            environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'), BC_TEST_MANUAL_HTTP=args.mode)
            build = str(args.c_build.resolve())
            subprocess.run(['swift', 'test', '--package-path', str(root / 'frontends/apple'),
                '--scratch-path', str(args.swift_scratch.resolve()), '-Xcc', '-I', '-Xcc', str(root / 'include'),
                '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'), '-Xlinker', '-L', '-Xlinker', build,
                '-Xlinker', '-rpath', '-Xlinker', build, '--filter', 'testFixtureDefaultUnknownHTTPSelectionIsSingleUse'],
                cwd=root, env=environment, check=True, timeout=120)
            mutations = [event for event in server.events if event[0] != 'GET']
            expected = [] if args.mode in ('cancel-choice', 'hard-denied') else [('POST', '/api/session')]
            if args.mode == 'html5':
                expected.append(('DELETE', '/api/session'))
            if mutations != expected:
                raise RuntimeError('No automatic or alternate login is allowed: ' + repr(mutations))
            print('Default inline manual HTTP fixture passed:', args.mode)
    finally:
        reference.Redfish.tearDownClass()


if __name__ == '__main__':
    main()
