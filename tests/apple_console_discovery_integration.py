"""Verify actual Apple parent discovery and separate Redfish/OEM ownership locally."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-build', type=Path, required=True)
    parser.add_argument('--swift-scratch', type=Path, default=Path('build-apple'))
    parser.add_argument('--logout-fails', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location('reference', root / 'tests/redfish_integration.py')
    reference = importlib.util.module_from_spec(spec)
    sys.argv = ['reference', str(args.c_build.resolve() / 'bcontrol-redfish-client')]
    spec.loader.exec_module(reference)
    sessions = '/redfish/v1/SessionService/Sessions'
    owned = sessions + '/fixture'
    manager = '/redfish/v1/Managers/node'
    attributes = manager + '/Attributes'
    oem = '/sysmgmt/2015/bmc/session'

    def get(handler):
        body = {
            '/redfish/v1/': {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot', 'RedfishVersion': '1.17.0',
                'SessionService': {'@odata.id': '/redfish/v1/SessionService'},
                'Managers': {'@odata.id': '/redfish/v1/Managers'}},
            '/redfish/v1/SessionService': {'@odata.type': '#SessionService.v1_1_0.SessionService',
                'ServiceEnabled': True, 'Sessions': {'@odata.id': sessions}},
            '/redfish/v1/Managers': {'@odata.type': '#ManagerCollection.ManagerCollection',
                'Members': [{'@odata.id': manager}]},
            manager: {'@odata.id': manager, 'Links': {'Oem': {'Dell': {'DellAttributes': [{'@odata.id': attributes}]}}}},
            attributes: {'@odata.type': '#DellAttributes.v1_0_0.DellAttributes',
                'Attributes': {'VirtualConsole.1.PluginType': 'eHTML5'}},
        }.get(handler.path)
        handler.server.events.append(('GET', handler.path))
        if handler.path.startswith('/redfish/v1/Managers'):
            if handler.headers.get('X-Auth-Token') != 'redfish-fixture':
                raise RuntimeError('Metadata must use the original Redfish owner')
        elif handler.path == '/redfish/v1/' and len(handler.server.events) == 1:
            if any(handler.headers.get(x) for x in ('Authorization', 'Cookie', 'X-Auth-Token')):
                raise RuntimeError('Public proof must remain anonymous')
        handler.reply(200 if body else 404, body or {})

    def post(handler):
        body = handler.rfile.read(int(handler.headers.get('Content-Length', '0')))
        handler.server.events.append(('POST', handler.path))
        if handler.path == sessions:
            if json.loads(body) != {'UserName': 'user', 'Password': 'test-secret'}:
                raise RuntimeError('Unexpected local Redfish login')
            handler.reply(201, {'@odata.type': '#Session.v1_0_0.Session', '@odata.id': owned},
                          [('X-Auth-Token', 'redfish-fixture'), ('Location', owned)])
        elif handler.path == oem:
            if any(handler.headers.get(x) for x in ('Authorization', 'Cookie', 'X-Auth-Token')):
                raise RuntimeError('Redfish credentials must not cross the OEM realm')
            if handler.headers.get('user') != '"user"' or handler.headers.get('password') != '"test-secret"':
                raise RuntimeError('Expected independently scoped OEM authentication')
            handler.reply(404, {})
        else:
            raise RuntimeError('Unexpected POST')

    def delete(handler):
        handler.server.events.append(('DELETE', handler.path))
        if handler.path != owned or handler.headers.get('X-Auth-Token') != 'redfish-fixture':
            raise RuntimeError('Only the owned Redfish session may be deleted')
        handler.reply(500 if args.logout_fails else 204, {})

    reference.Handler.do_GET, reference.Handler.do_POST, reference.Handler.do_DELETE = get, post, delete
    reference.Redfish.setUpClass()
    try:
        with reference.Redfish().fixture() as server:
            server.events = []
            environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
            environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'),
                BC_TEST_CONSOLE_DISCOVERY_IDRAC='failed' if args.logout_fails else 'closed')
            build = str(args.c_build.resolve())
            subprocess.run(['swift', 'test', '--package-path', str(root / 'frontends/apple'),
                '--scratch-path', str(args.swift_scratch.resolve()), '-Xcc', '-I', '-Xcc', str(root / 'include'),
                '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'), '-Xlinker', '-L', '-Xlinker', build,
                '-Xlinker', '-rpath', '-Xlinker', build,
                '--filter', 'testFixtureIDRACDiscoveryClosesRedfishBeforeOEMAuthentication'],
                cwd=root, env=environment, check=True, timeout=120)
            mutations = [event for event in server.events if event[0] != 'GET']
            expected = [('POST', sessions), ('DELETE', owned)]
            if not args.logout_fails:
                expected.append(('POST', oem))
            if mutations != expected:
                raise RuntimeError('Owner transition order differs: ' + repr(mutations))
            print('Apple parent iDRAC realm ownership passed:', mutations)
    finally:
        reference.Redfish.tearDownClass()


if __name__ == '__main__':
    main()
