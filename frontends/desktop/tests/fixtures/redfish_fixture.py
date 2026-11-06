#!/usr/bin/env python3
"""桌面端绑定测试用 Redfish HTTPS 夹具。

用法: redfish_fixture.py <port>
打印 READY 后持续服务，直到进程被终止。
覆盖：Session 认证（POST/DELETE SessionService/Sessions）、ServiceRoot、
Systems 集合/成员、Chassis、Sensors 集合/成员（含 CPU 温度上下文）。
"""
import base64
import http.server
import json
import os
import ssl
import subprocess
import sys
import time
import tempfile
from pathlib import Path

USER = 'fixture-user'
PASSWORD = 'fixture-password'
BASE = '/redfish/v1/Systems'
CHASSIS = '/redfish/v1/Chassis/rack-1'
SENSORS = CHASSIS + '/Sensors'
RESET = BASE + '/host-A/Actions/ComputerSystem.Reset'
CPU_SENSOR = SENSORS + '/cpu1'
AMBIENT_SENSOR = SENSORS + '/ambient'
MEDIA_MANAGER = '/redfish/v1/Managers/media'
MEDIA = MEDIA_MANAGER + '/VirtualMedia/cd'
TASKS = '/redfish/v1/queue/jobs'


def make_cert(directory):
    imported = os.environ.get('BC_FIXTURE_CERT')
    if imported:
        return imported
    cert = Path(directory) / 'fixture.pem'
    subprocess.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', str(cert),
         '-out', str(cert), '-days', '1', '-nodes', '-subj', '/CN=localhost',
         '-addext', 'subjectAltName=IP:127.0.0.1'],
        check=True, capture_output=True)
    return str(cert)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def token_ok(self):
        return self.headers.get('X-Auth-Token') == 'fixture-token'

    def reply(self, status, body=None, headers=()):
        payload = b'' if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def media_task(self, task, state):
        return {'@odata.type': '#Task.v1_7_4.Task', '@odata.id': task['uri'],
                'Id': task['uri'].rsplit('/', 1)[1], 'StartTime': '2026-11-04T00:00:00Z',
                'TaskState': state, 'TaskStatus': 'OK', 'Payload': {
                    'HttpOperation': 'POST', 'TargetUri': task['target'],
                    'JsonBody': json.dumps({'Image': task['image']})}}

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = json.loads(self.rfile.read(length) or b'{}')
        if self.path == '/redfish/v1/SessionService/Sessions':
            if body == {'UserName': USER, 'Password': PASSWORD}:
                self.server.sessions.add('/redfish/v1/SessionService/Sessions/1')
                self.reply(201, {'@odata.type': '#Session.v1_6_0.Session',
                                 '@odata.id': '/redfish/v1/SessionService/Sessions/1', 'Id': '1'},
                           [('X-Auth-Token', 'fixture-token'),
                            ('Location', '/redfish/v1/SessionService/Sessions/1')])
            else:
                self.reply(401, {'error': {'code': 'Base.1.0.GeneralError', 'message': 'auth'}})
            return
        if self.path == RESET:
            if not self.token_ok():
                return self.reply(401)
            action = body.get('ResetType')
            self.server.power = 'Off' if action in ('ForceOff', 'GracefulShutdown', 'PowerCycle') else 'On'
            return self.reply(204)
        if self.path in (MEDIA + '/Actions/InsertMedia', MEDIA + '/Actions/EjectMedia'):
            if not self.token_ok():
                return self.reply(401)
            if body.get('Image') == 'https://images.invalid/rejected.iso':
                return self.reply(403)
            if body.get('Image') == 'https://images.invalid/uncertain.iso':
                return self.reply(500)
            if self.path.endswith('/EjectMedia'):
                if self.server.media_image == 'https://images.invalid/eject-rejected.iso':
                    return self.reply(403)
                if self.server.media_image == 'https://images.invalid/eject-uncertain.iso':
                    return self.reply(500)
                if self.server.media_image == 'https://images.invalid/eject-readback-failed.iso':
                    self.server.media_image = None
                    self.server.media_readback_failed = True
                    return self.reply(204)
            task_uri = TASKS + '/' + str(len(self.server.media_tasks) + 1)
            task = {'uri': task_uri, 'target': self.path, 'image': body.get('Image'),
                    'inserting': self.path.endswith('/InsertMedia')}
            self.server.media_tasks[task_uri] = task
            return self.reply(202, self.media_task(task, 'Running'), [('Location', task_uri), ('Retry-After', '0')])
        if os.environ.get('BC_FIXTURE_HUAWEI') == '1' and self.path == '/redfish/v1/Managers/node/KvmService/Actions/KvmService.ExportKvmStartupFile':
            if not self.token_ok():
                return self.reply(401)
            if body != {'Mode': 'Shared'}:
                return self.reply(400)
            return self.reply(200, b'<jnlp><applet-desc>'
                b'<param name="IPA" value="127.0.0.1"/><param name="port" value="2198"/>'
                b'<param name="verifyValue" value="fixture"/>'
                b'<param name="decrykey" value="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"/>'
                b'</applet-desc></jnlp>')
        self.reply(404)

    def do_PATCH(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = json.loads(self.rfile.read(length) or b'{}')
        if not self.token_ok():
            return self.reply(401)
        if self.path == BASE + '/host-A':
            boot = body.get('Boot')
            if not isinstance(boot, dict):
                return self.reply(400, {'error': {'message': 'boot'}})
            if boot.get('BootSourceOverrideEnabled') == 'Disabled':
                self.server.boot['BootSourceOverrideEnabled'] = 'Disabled'
                self.server.boot['BootSourceOverrideTarget'] = 'None'
            else:
                for key in ('BootSourceOverrideEnabled', 'BootSourceOverrideTarget', 'BootSourceOverrideMode'):
                    if key in boot:
                        self.server.boot[key] = boot[key]
            return self.reply(204)
        self.reply(404)

    def do_DELETE(self):
        time.sleep(self.server.logout_delay)
        if self.path in self.server.sessions:
            self.server.sessions.discard(self.path)
            self.reply(204)
            return
        self.reply(404)

    def do_GET(self):
        if self.path in ('/redfish/v1/', '/redfish/v1'):
            time.sleep(self.server.root_delay)
            return self.reply(200, {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot',
                                    'RedfishVersion': '1.17.0',
                                    'Systems': {'@odata.id': BASE},
                                    'Chassis': {'@odata.id': '/redfish/v1/Chassis'},
                                    'Managers': {'@odata.id': '/redfish/v1/Managers'},
                                    'SessionService': {'@odata.id': '/redfish/v1/SessionService'},
                                    'TaskService': {'@odata.id': '/redfish/v1/queue'}})
        if self.path == '/redfish/v1/SessionService':
            return self.reply(200, {'@odata.type': '#SessionService.v1_2_0.SessionService',
                                    'ServiceEnabled': True,
                                    'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}})
        if not self.token_ok():
            return self.reply(401)
        if os.environ.get('BC_FIXTURE_HUAWEI') == '1':
            manager = '/redfish/v1/Managers/node'
            kvm = manager + '/KvmService'
            if self.path == '/redfish/v1/Managers':
                return self.reply(200, {'@odata.type': '#ManagerCollection.ManagerCollection',
                    'Members': [{'@odata.id': manager}]})
            if self.path == manager:
                return self.reply(200, {'@odata.id': manager, '@odata.type': '#Manager.v1_0_0.Manager',
                    'Manufacturer': 'Unrelated vendor text', 'Oem': {'AnyNamespace': {
                        'KvmService': {'@odata.id': kvm}, 'Attributes': {'@odata.id': manager + '/Attributes'}},
                        'OtherNamespace': {'DellAttributes': {'@odata.id': manager + '/UnsupportedAttributes'}}}})
            if self.path == manager + '/UnsupportedAttributes':
                return self.reply(200, {'@odata.id': self.path, '@odata.type': '#UnknownAttributes.v9_0_0.Attributes',
                    'Attributes': {'VirtualConsole.1.PluginType': 'eHTML5'}})
            if self.path == manager + '/Attributes':
                return self.reply(200, {'@odata.id': self.path, '@odata.type': '#DellAttributes.v1_0_0.DellAttributes',
                    'Attributes': {'VirtualConsole.1.PluginType': 'eHTML5'}})
            if self.path == kvm:
                return self.reply(200, {'@odata.id': kvm, '@odata.type': '#HwKvmService.v1_0_0.HwKvmService',
                    'NumberOfActivatedSessions': 0, 'AutoOSLockEnabled': False,
                    'Actions': {'#KvmService.ExportKvmStartupFile': {
                        'target': kvm + '/Actions/KvmService.ExportKvmStartupFile',
                        '@Redfish.ActionInfo': kvm + '/ExportActionInfo'}}})
            if self.path == kvm + '/ExportActionInfo':
                return self.reply(200, {'@odata.type': '#ActionInfo.v1_0_0.ActionInfo', 'Parameters': [
                    {'Name': 'Mode', 'Required': True, 'DataType': 'String', 'AllowableValues': ['Shared', 'Private']}]})
        if self.path == '/redfish/v1/Managers':
            return self.reply(200, {'@odata.type': '#ManagerCollection.ManagerCollection',
                                   'Members': [{'@odata.id': MEDIA_MANAGER}]})
        if self.path == MEDIA_MANAGER:
            return self.reply(200, {'@odata.type': '#Manager.v1_0_0.Manager', 'Id': 'media',
                                   'VirtualMedia': {'@odata.id': MEDIA_MANAGER + '/VirtualMedia'}})
        if self.path == MEDIA_MANAGER + '/VirtualMedia':
            return self.reply(200, {'@odata.type': '#VirtualMediaCollection.VirtualMediaCollection',
                                   'Members': [{'@odata.id': MEDIA}]})
        if self.path == MEDIA:
            if getattr(self.server, 'media_readback_failed', False):
                return self.reply(500)
            return self.reply(200, {'@odata.type': '#VirtualMedia.v1_6_1.VirtualMedia', 'Id': 'cd',
                                   'Inserted': self.server.media_image is not None, 'Image': self.server.media_image,
                                   'Actions': {'#VirtualMedia.InsertMedia': {'target': MEDIA + '/Actions/InsertMedia'},
                                               '#VirtualMedia.EjectMedia': {'target': MEDIA + '/Actions/EjectMedia'}}})
        if self.path == '/redfish/v1/queue':
            return self.reply(200, {'@odata.type': '#TaskService.v1_2_0.TaskService', 'ServiceEnabled': True,
                                   'Tasks': {'@odata.id': TASKS}})
        if self.path == TASKS:
            return self.reply(200, {'@odata.type': '#TaskCollection.TaskCollection',
                                   'Members': [{'@odata.id': uri} for uri in self.server.media_tasks]})
        if self.path in self.server.media_tasks:
            task = self.server.media_tasks[self.path]
            self.server.media_image = task['image'] if task['inserting'] else None
            return self.reply(200, self.media_task(task, 'Completed'))
        if self.path == BASE:
            return self.reply(200, {'@odata.type': '#ComputerSystemCollection.ComputerSystemCollection',
                                    'Members': [{'@odata.id': BASE + '/host-A'}]})
        if self.path == BASE + '/host-A':
            return self.reply(200, {'@odata.type': '#ComputerSystem.v1_22_0.ComputerSystem',
                                    'Id': 'host-A', 'Name': 'Fixture system', 'PowerState': self.server.power,
                                    'Manufacturer': 'FixtureVendor', 'Model': 'FixtureModel',
                                    'SerialNumber': 'fixture-serial', 'UUID': 'fixture-uuid',
                                    'HostName': 'fixture-host', 'Links': {'Chassis': [{'@odata.id': CHASSIS}]},
                                    'Actions': {'#ComputerSystem.Reset': {
                                        'target': RESET,
                                        'ResetType@Redfish.AllowableValues': ['On', 'ForceOff',
                                            'GracefulShutdown', 'GracefulRestart', 'ForceRestart', 'Nmi',
                                            'ForceOn', 'PushPowerButton', 'PowerCycle']}},
                                    'Boot': self.server.boot})
        if self.path == '/redfish/v1/Chassis':
            return self.reply(200, {'@odata.type': '#ChassisCollection.ChassisCollection',
                                    'Members': [{'@odata.id': CHASSIS}]})
        if self.path == CHASSIS:
            return self.reply(200, {'@odata.type': '#Chassis.v1_22_0.Chassis', 'Id': 'rack-1',
                                    'Links': {'ComputerSystems': [{'@odata.id': BASE + '/host-A'}]},
                                    'Sensors': {'@odata.id': SENSORS}})
        if self.path == SENSORS:
            return self.reply(200, {'@odata.type': '#SensorCollection.SensorCollection',
                                    'Members': [{'@odata.id': CPU_SENSOR}, {'@odata.id': AMBIENT_SENSOR}]})
        if self.path == CPU_SENSOR:
            return self.reply(200, {'@odata.type': '#Sensor.v1_11_1.Sensor', 'Id': 'cpu1',
                                    'Name': 'CPU1 temperature', 'Reading': 41.5, 'ReadingType': 'Temperature',
                                    'ReadingUnits': 'Cel', 'Status': {'State': 'Enabled', 'Health': 'OK'},
                                    'PhysicalContext': 'CPU', 'ReadingBasis': 'Zero', 'Enabled': True,
                                    'RelatedItem': [{'@odata.id': BASE + '/host-A/Processors/1'}],
                                    'Links': {'Chassis': [{'@odata.id': CHASSIS}],
                                              'ComputerSystems': [{'@odata.id': BASE + '/host-A'}]}})
        if self.path == AMBIENT_SENSOR:
            return self.reply(200, {'@odata.type': '#Sensor.v1_11_1.Sensor', 'Id': 'ambient',
                                    'Name': 'Ambient temperature', 'Reading': 22.5, 'ReadingType': 'Temperature',
                                    'ReadingUnits': 'Cel', 'Status': {'State': 'Enabled', 'Health': 'OK'},
                                    'PhysicalContext': 'Intake', 'ReadingBasis': 'Zero', 'Enabled': True,
                                    'RelatedItem': [{'@odata.id': CHASSIS}],
                                    'Links': {'Chassis': [{'@odata.id': CHASSIS}]}})
        self.reply(404)


def main():
    port = int(sys.argv[1])
    cert_dir = tempfile.mkdtemp(prefix='bcontrol-redfish-')
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    cert = None if os.environ.get('BC_FIXTURE_PLAIN') == '1' else make_cert(cert_dir)
    server.root_delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0
    server.logout_delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0
    server.sessions = set()
    server.media_tasks = {}
    server.media_image = None
    server.power = 'On'
    server.boot = {
        'BootSourceOverrideEnabled': 'Disabled', 'BootSourceOverrideTarget': 'None',
        'BootSourceOverrideMode': 'UEFI',
        'BootSourceOverrideTarget@Redfish.AllowableValues': ['None', 'Pxe', 'Hdd', 'Cd', 'BiosSetup', 'Usb', 'UefiShell'],
        'BootSourceOverrideEnabled@Redfish.AllowableValues': ['Disabled', 'Once', 'Continuous'],
        'BootSourceOverrideMode@Redfish.AllowableValues': ['Legacy', 'UEFI'],
    }
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f'READY {server.server_port} {cert or "plain"}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
