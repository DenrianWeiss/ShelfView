"""Verify Apple Shared/explicit Private launch calls against a local TLS fixture."""
import argparse
import importlib.util
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import time
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-build', type=Path, required=True)
    parser.add_argument('--swift-scratch', type=Path, default=Path('build-apple'))
    parser.add_argument('--automatic', action='store_true')
    parser.add_argument('--discovery', action='store_true')
    parser.add_argument('--discovery-model', action='store_true')
    parser.add_argument('--default', action='store_true')
    parser.add_argument('--discovery-refused', choices=['unauthenticated', 'wrong-type', 'timeout', 'cancel'])
    parser.add_argument('--two-step', action='store_true')
    parser.add_argument('--private-fallback', choices=['confirm', 'cancel', 'timeout', 'hard-refusal', 'uncertain',
                        'no-handler', 'no-private', 'changed-after-prompt', 'private-reject', 'model-cancel', 'uncooperative', 'task-cancel', 'console-close'])
    args = parser.parse_args()
    if args.discovery_model:
        args.discovery = True
    if args.private_fallback or args.discovery or args.discovery_refused:
        args.automatic = True
    root = Path(__file__).resolve().parent.parent
    c_build, scratch = args.c_build.resolve(), args.swift_scratch.resolve()
    spec = importlib.util.spec_from_file_location('reference', root / 'tests/redfish_integration.py')
    reference = importlib.util.module_from_spec(spec)
    saved = sys.argv
    try:
        sys.argv = ['reference', str(c_build / 'bcontrol-redfish-client')]
        spec.loader.exec_module(reference)
    finally:
        sys.argv = saved
    target = '/redfish/v1/Managers/node/KvmService/Actions/KvmService.ExportKvmStartupFile'
    if args.automatic:
        target = '/redfish/v1/managers/node/kvmservice/actions/kvmservice.exportkvmstartupfile'
    startup = b'''<jnlp><applet-desc>
      <param name="IPA" value="127.0.0.1"/><param name="port" value="2198"/>
      <param name="verifyValue" value="1234567890"/>
      <param name="verifyValueExt" value="00112233445566778899aabbccddeeff"/>
      <param name="decrykey" value="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"/>
      <param name="privilege" value="4"/><param name="title" value="fixture"/>
      </applet-desc></jnlp>'''
    download = '/redfish/v1/Managers/node/Actions/Oem/Huawei/Manager.GeneralDownload'
    if args.automatic:
        download = '/redfish/v1/managers/node/actions/oem/huawei/manager.generaldownload'
    native = None
    native_connections = []
    if args.discovery_model:
        native = socket.socket()
        native.bind(('127.0.0.1', 0))
        native.listen(1)
        native.settimeout(15)
        startup = startup.replace(b'value="2198"', ('value="' + str(native.getsockname()[1]) + '"').encode())
        def close_native_peer():
            try:
                connection, _ = native.accept()
                native_connections.append(1)
                connection.close()
            except OSError:
                pass
        threading.Thread(target=close_native_peer, daemon=True).start()
    original = reference.Handler.do_POST

    def post(handler):
        if handler.path not in (target, download):
            return original(handler)
        body = json.loads(handler.rfile.read(int(handler.headers.get('Content-Length', '0'))))
        handler.server.posts.append((handler.path, body))
        if not handler.headers.get('Authorization') and not handler.headers.get('X-Auth-Token'):
            handler.reply(401, b'')
            return
        if args.private_fallback and handler.path == target:
            if body.get('Mode') == 'Shared':
                if args.private_fallback == 'uncertain':
                    handler.connection.shutdown(socket.SHUT_RDWR)
                    handler.close_connection = True
                    return
                error = {'error': {'code': 'Base.1.18.GeneralError', '@Message.ExtendedInfo': [{
                    'MessageId': 'Base.1.18.ActionParameterValueNotInList',
                    'MessageArgs': ['Shared', 'Mode', 'KvmService.ExportKvmStartupFile']}]}}
                return handler.reply(403 if args.private_fallback == 'hard-refusal' else 400, error)
            if args.private_fallback == 'private-reject':
                return handler.reply(403, {'error': {'code': 'Base.1.18.InsufficientPrivilege'}})
        handler.reply(201, {}) if args.two_step and handler.path == target else handler.reply(200, startup)

    original_get = reference.Handler.do_GET
    def get(handler):
        if args.discovery or args.discovery_refused:
            handler.server.discovery_requests.append((handler.path, handler.headers.get("Authorization"), handler.headers.get("Cookie")))
        if args.discovery_refused and handler.path == "/redfish/v1/":
            if args.discovery_refused in ("timeout", "cancel"):
                time.sleep(0.4)
                return
            return handler.reply(401 if args.discovery_refused == "unauthenticated" else 200, {"@odata.type": "#Manager.v1_0_0.Manager"})
        if not args.automatic:
            return original_get(handler)
        manager = '/redfish/v1/Managers/node'
        resource = manager + '/KvmService'
        info = resource + '/ExportKvmStartupFileActionInfo'
        bodies = {
            '/redfish/v1/Managers': {'@odata.type': '#ManagerCollection.ManagerCollection', 'Members': [{'@odata.id': manager}]},
            manager: {'@odata.id': '/redfish/v1/managers/node', 'Oem': {'Huawei': {'KvmService': {'@odata.id': resource}}}},
            resource: {'@odata.id': '/redfish/v1/managers/node/kvmservice', '@odata.type': '#HwKvmService.v1_0_0.HwKvmService',
                       'Actions': {'#KvmService.ExportKvmStartupFile': {'target': target, '@Redfish.ActionInfo': info}}},
            info: {'@odata.type': '#ActionInfo.v1_0_0.ActionInfo', 'Parameters': [
                {'Name': 'Mode', 'Required': True, 'DataType': 'String', 'AllowableValues': ['Shared', 'Private']}]},
        }
        if args.two_step:
            bodies[manager]['Actions'] = {'Oem': {'Huawei': {'#Manager.GeneralDownload': {'target': download}}}}
            bodies[info]['Parameters'] += [
                {'Name': 'Type', 'Required': True, 'DataType': 'String', 'AllowableValues': ['URI']},
                {'Name': 'Content', 'Required': True, 'DataType': 'String'}]
        if handler.path == info and args.private_fallback:
            handler.server.private_info_reads += 1
            remove = (args.private_fallback == 'no-private' and handler.server.private_info_reads >= 2) or (
                args.private_fallback == 'changed-after-prompt' and handler.server.private_info_reads >= 3)
            if remove:
                bodies[info]['Parameters'][0]['AllowableValues'] = ['Shared']
        if handler.path in bodies:
            handler.server.requests.append(handler.path)
            return handler.reply(200, bodies[handler.path])
        return original_get(handler)
    reference.Handler.do_GET = get
    reference.Handler.do_POST = post
    reference.Redfish.setUpClass()
    try:
        with reference.Redfish().fixture() as server:
            server.private_info_reads = 0
            server.discovery_requests = []
            environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
            environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                               BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'),
                               BC_TEST_HUAWEI_LAUNCH_FIXTURE='1', BC_TEST_HUAWEI_PARENT_FIXTURE='1' if args.automatic else '0')
            if args.default:
                environment['BC_TEST_CONSOLE_DEFAULT'] = '1'
            if args.discovery_model:
                environment['BC_TEST_CONSOLE_DISCOVERY_MODEL'] = '1'
            if args.discovery or args.discovery_refused:
                environment['BC_TEST_CONSOLE_STARTUP_DISCOVERY'] = '1'
                if args.discovery_refused:
                    environment['BC_TEST_CONSOLE_STARTUP_REFUSED'] = args.discovery_refused
            if args.private_fallback:
                environment['BC_TEST_HUAWEI_PRIVATE_MODE'] = args.private_fallback
            command = ['swift', 'test', '--package-path', str(root / 'frontends/apple'),
                       '--scratch-path', str(scratch), '-Xcc', '-I', '-Xcc', str(root / 'include'),
                       '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'),
                       '-Xlinker', '-L', '-Xlinker', str(c_build),
                       '-Xlinker', '-rpath', '-Xlinker', str(c_build),
                       '--filter', 'testFixtureRedfishDiscoveryDrivesTheActualHuaweiBackend' if args.discovery_model else (
                           'testFixtureDiscoveredHuaweiReusesOwner' if args.discovery or args.discovery_refused else (
                           'testFixtureHuaweiPrivateFallback' if args.private_fallback else (
                           'testFixtureHuaweiAutomaticStartup' if args.automatic else 'testFixtureHuaweiSharedLaunchUsesAuthenticatedEndpoint')))]
            subprocess.run(command, env=environment, cwd=root, check=True, timeout=120)
            if args.discovery_refused:
                if server.posts or len(server.discovery_requests) != 1 or server.discovery_requests[0][1:] != (None, None):
                    raise RuntimeError("Rejected public proof must not send credentials or login")
                print("Anonymous discovery refused safely:", args.discovery_refused)
                return
            if args.discovery_model and native_connections != [1]:
                raise RuntimeError("Actual parent backend must connect to the native fixture")
            if args.discovery:
                roots = [entry for entry in server.discovery_requests if entry[0] == "/redfish/v1/"]
                if len(roots) != (5 if args.default else 4) or any(cookie for _, _, cookie in roots) or sum(auth is None for _, auth, _ in roots) != (3 if args.default else 2):
                    raise RuntimeError("Expected fresh anonymous proof and one Basic login only: " + repr(roots))
                if sum(path.endswith('/ExportKvmStartupFileActionInfo') for path, _, _ in server.discovery_requests) != 1:
                    raise RuntimeError("Startup must reuse the original metadata")
            if args.private_fallback:
                exports = [body for path, body in server.posts if path == target]
                modes = [body.get('Mode') for body in exports]
                expected_modes = ['Shared', 'Private'] * 2 if args.private_fallback == 'confirm' else (
                    ['Shared', 'Private'] if args.private_fallback == 'private-reject' else ['Shared'])
                if modes != expected_modes or any(path not in (target, download) for path, _ in server.posts):
                    raise RuntimeError('Unexpected Private fallback export sequence: ' + repr(modes))
                downloads = [body for path, body in server.posts if path == download]
                expected_downloads = [{'TransferProtocol': 'HTTPS', 'Path': body['Content']} for body in exports
                    if body.get('Mode') == 'Private'] if args.two_step and args.private_fallback == 'confirm' else []
                if downloads != expected_downloads:
                    raise RuntimeError('Unexpected download after rejected/uncertain export')
                expected_reads = 6 if args.private_fallback == 'confirm' else (
                    3 if args.private_fallback in ('private-reject', 'changed-after-prompt') else (
                    2 if args.private_fallback in ('cancel', 'timeout', 'uncooperative', 'task-cancel', 'console-close', 'no-private', 'model-cancel') else 1))
                if server.private_info_reads != expected_reads:
                    raise RuntimeError('Unexpected metadata revalidation count: ' + str(server.private_info_reads))
                print('Apple Huawei Private fallback passed:', args.private_fallback, 'POST count:', len(server.posts))
                return
            expected = [(target, {'Mode': 'Shared'})] if args.automatic else [(target, {'Mode': 'Shared'}), (target, {'Mode': 'Private'})]
            if args.two_step:
                if len(server.posts) != 2 or server.posts[0][0] != target:
                    raise RuntimeError('Expected one export and one download')
                export = server.posts[0][1]
                if export.get('Mode') != 'Shared' or export.get('Type') != 'URI' or not export.get('Content', '').startswith('/tmp/web/kvm'):
                    raise RuntimeError('Unexpected export request')
                expected = [(target, export), (download, {'TransferProtocol': 'HTTPS', 'Path': export['Content']})]
            if server.posts != expected:
                raise RuntimeError('Expected exactly one Shared and one explicitly confirmed Private POST')
            print('Apple Huawei launch fixture passed; expected POST count:', len(expected))
    finally:
        if native:
            native.close()
        reference.Redfish.tearDownClass()


if __name__ == '__main__':
    main()
