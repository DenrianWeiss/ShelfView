import contextlib
import base64
import http.server
import json
import os
from pathlib import Path
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

CLIENT = str(Path(sys.argv.pop(1)).resolve())
BASE = '/redfish/v1/Systems'
TARGET = BASE + '/host-A/Actions/CustomReset'
INFO = BASE + '/host-A/ResetActionInfo'
TASK = '/redfish/v1/TaskService/Tasks/7'
MONITOR = '/redfish/v1/TaskService/TaskMonitors/7'
SENSOR = '/redfish/v1/Chassis/rack-1/Sensors/ambient'
CHASSIS_COLLECTION = '/redfish/v1/Chassis'
CHASSIS = CHASSIS_COLLECTION + '/rack-1'
SENSORS = CHASSIS + '/Sensors'
VM_COLLECTION = '/redfish/v1/Managers/mgr1/VirtualMedia'
VM_MEDIA = VM_COLLECTION + '/cd'
VM_INSERT = VM_MEDIA + '/Actions/InsertMedia'
VM_EJECT = VM_MEDIA + '/Actions/EjectMedia'
IRMC_SYSTEM = BASE + '/irmc-system'
IRMC_MEDIA = IRMC_SYSTEM + '/Oem/ts_fujitsu/VirtualMedia'
IRMC_ACTION = IRMC_SYSTEM + '/Actions/Oem/FTSComputerSystem.VirtualMedia'
IRMC_SCHEMA = 'http://ts.fujitsu.com/redfish-schemas/v1/FTSSchema.v1_0_0#'
MANAGERS = '/redfish/v1/Managers'
MANAGER = MANAGERS + '/bmc'
NETWORK_PROTOCOL = MANAGER + '/NetworkProtocol'
ETH_COLLECTION = MANAGER + '/EthernetInterfaces'
ETH0 = ETH_COLLECTION + '/eth0'
ETH1 = ETH_COLLECTION + '/eth1'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def task(self):
        return {'@odata.type': '#Task.v1_4_3.Task', '@odata.id': TASK, 'Id': '7', 'TaskState': self.server.task_state,
                'TaskStatus': 'Critical' if self.server.task_state == 'Exception' else 'OK', 'PercentComplete': 33,
                'TaskMonitor': MONITOR, 'Messages': [{'MessageId': 'TaskEvent.1.0.TaskStarted', 'Message': 'Started'}]}

    def do_GET(self):
        self.server.requests.append(self.path)
        mode = self.server.mode
        status = 200
        if self.path == '/redfish/v1/':
            body = {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot', 'RedfishVersion': '1.17.0', 'Systems': {'@odata.id': BASE}, 'Chassis': {'@odata.id': CHASSIS_COLLECTION},
                    'Managers': {'@odata.id': MANAGERS if mode != 'external-managers' else 'https://different.invalid/Managers'}}
            if mode != 'missing-task-service':
                body['TaskService'] = {'@odata.id': 'https://different.invalid/tasks' if mode == 'external-task-service' else '/redfish/v1/work-queue'}
            if mode == 'auth-isolation':
                basic, token = self.headers.get('Authorization'), self.headers.get('X-Auth-Token')
                expected = 'Basic ' + base64.b64encode(b'fixture-user:fixture-password').decode()
                if basic == expected and token is None:
                    self.server.auth_seen.append('basic')
                elif token == 'fixture-token' and basic is None:
                    self.server.auth_seen.append('token')
                    self.reply(200, body, [('X-Auth-Token', 'response-token')]); return
                elif token is None and basic is None:
                    self.server.auth_seen.append('anonymous'); status = 401
                else:
                    self.server.auth_seen.append('invalid'); status = 400
            elif mode == 'missing':
                del body['Systems']
            elif mode == 'error':
                body = {'error': {'code': 'Base.1.0.GeneralError', 'message': 'simulated'}}
            elif mode == 'malformed':
                body = b'{"broken"'
            elif mode == 'bad-version':
                body['RedfishVersion'] = 'not-a-version'
            elif mode == 'missing-chassis':
                del body['Chassis']
        elif self.path == '/redfish/v1/Managers/arbitrary-controller':
            body = {'@odata.type': '#FutureManager.v9_0_0.FutureManager', 'Id': 'arbitrary-controller',
                    'Manufacturer': 'fixture', 'FirmwareVersion': 'fixture-only',
                    'Oem': {key: {'UnknownCapability': {'enabled': True, 'limit': 4294967297}}
                            for key in ('AMI', 'Hpe', 'Dell', 'Huawei', 'OpenBmc', 'FutureVendor')},
                    'Links': {'VendorExtension': {'@odata.id': '/redfish/v1/Oem/fixture/Capability'}},
                    'FutureProperty': ['preserve', None, 9007199254740993]}
        elif self.path == CHASSIS_COLLECTION:
            body = {'@odata.type': '#ChassisCollection.ChassisCollection', 'Members': [{'@odata.id': CHASSIS}]}
        elif self.path == CHASSIS:
            body = {'@odata.type': '#Chassis.v1_22_0.Chassis', 'Id': 'rack-1', 'Sensors': {'@odata.id': SENSORS}}
            if mode in ('chassis-subresource-links', 'chassis-mixed-links'):
                links = [CHASSIS + '/Thermal', CHASSIS + '/NetworkAdapters/1']
                if mode == 'chassis-mixed-links':
                    links += [BASE + '/A', CHASSIS + '/Oem/Systems/A', CHASSIS + '-other/Oem/Systems/A']
                body['Links'] = {'ComputerSystems': [{'@odata.id': uri} for uri in links]}
            if mode == 'missing-sensors':
                del body['Sensors']
            elif mode == 'external-sensors':
                body['Sensors']['@odata.id'] = 'https://different.invalid/Sensors'
        elif self.path == SENSORS or self.path.startswith(SENSORS + '?'):
            second = '?page=2' in self.path
            members = [SENSORS + '/voltage'] if second else [SENSOR]
            if mode == 'sensor-duplicates' and second:
                members.append(SENSOR)
            body = {'@odata.type': '#SensorCollection.SensorCollection', 'Members': [{'@odata.id': x} for x in members]}
            if not second:
                body['Members@odata.nextLink'] = SENSORS + '?page=2'
            if mode == 'sensor-cycle':
                body['Members@odata.nextLink'] = SENSORS
            elif mode == 'empty-sensors':
                body = {'@odata.type': '#SensorCollection.SensorCollection', 'Members': []}
            elif mode == 'sensor-external-member':
                body['Members'][0]['@odata.id'] = 'https://different.invalid/sensor'
            elif mode == 'sensor-wrong-collection':
                body['@odata.type'] = '#ComputerSystemCollection.ComputerSystemCollection'
        elif self.path == '/redfish/v1/work-queue':
            body = {'@odata.type': '#TaskService.v1_2_0.TaskService', 'Tasks': {'@odata.id': '/redfish/v1/TaskService/Tasks'}}
            if mode == 'missing-tasks':
                del body['Tasks']
            elif mode == 'external-tasks':
                body['Tasks']['@odata.id'] = 'https://different.invalid/tasks'
            elif mode == 'wrong-task-service':
                body['@odata.type'] = '#Manager.v1_0_0.Manager'
        elif self.path == TASK:
            body = self.task()
            if self.server.monitor_gone:
                del body['TaskMonitor']
            if mode == 'bad-percent':
                body['PercentComplete'] = 101
            elif mode == 'null-percent':
                body['PercentComplete'] = None
        elif self.path.startswith('/redfish/v1/TaskService/Tasks'):
            body = {'@odata.type': '#TaskCollection.TaskCollection', 'Members': [{'@odata.id': TASK}]}
            if mode == 'empty-tasks':
                body['Members'] = []
            elif mode == 'task-pages':
                if '?' in self.path:
                    body['Members'].append({'@odata.id': TASK + '-next'})
                else:
                    body['Members@odata.nextLink'] = self.path + '?page=2'
            elif mode == 'task-cycle':
                body['Members@odata.nextLink'] = self.path
        elif self.path == MONITOR:
            if self.server.monitor_gone:
                self.reply(404, {'error': {'code': 'Base.1.0.ResourceMissingAtURI'}})
            elif mode.startswith('monitor-final'):
                responses = {'monitor-final-error': (200, {'error': {'code': 'Base.1.0.GeneralError'}}),
                             'monitor-final-created': (201, {'@odata.id': BASE + '/created'}),
                             'monitor-final-bytes': (200, b'original operation result')}
                self.reply(*responses[mode])
            elif self.server.task_state != 'Running':
                self.server.monitor_gone = True
                self.reply(204, b'')
            else:
                headers = [('Location', MONITOR), ('Retry-After', '1')]
                if mode == 'duplicate-header':
                    headers.append(('location', MONITOR))
                elif mode == 'duplicate-token':
                    headers += [('X-Auth-Token', 'one'), ('x-auth-token', 'two')]
                elif mode == 'bad-token-header':
                    headers += [('X-Auth-Token', 'bad token')]
                elif mode == 'oversized-location':
                    headers[0] = ('Location', '/' + 'x' * 9000)
                elif mode == 'external-monitor':
                    headers[0] = ('Location', 'https://different.invalid/monitor')
                elif mode == 'retry-date':
                    headers[1] = ('Retry-After', 'Wed, 21 Oct 2026 07:28:00 GMT')
                elif mode == 'interim':
                    self.wfile.write(b'HTTP/1.1 103 Early Hints\r\nLocation: https://ignored.invalid/\r\n\r\n')
                elif mode == 'header-budget':
                    headers += [('X-Padding-' + str(i), 'x' * 1500) for i in range(48)]
                self.reply(202, self.task(), headers)
            return
        elif self.path == VM_MEDIA:
            body = {'@odata.type': '#VirtualMedia.v1_7_0.VirtualMedia', 'Id': 'cd', 'Name': 'Virtual CD',
                    'MediaTypes': ['CD', 'DVD'], 'Inserted': self.server.vm_inserted,
                    'WriteProtected': True, 'Image': self.server.vm_image, 'ImageName': 'image.iso',
                    'ConnectedVia': 'URI' if self.server.vm_inserted else 'NotConnected',
                    'Actions': {'#VirtualMedia.InsertMedia': {'target': VM_INSERT},
                                '#VirtualMedia.EjectMedia': {'target': VM_EJECT}}}
            if mode == 'vm-null-state':
                body['WriteProtected'] = None
                body['Inserted'] = None
            elif mode == 'vm-missing-state':
                del body['Inserted']
            if mode == 'vm-no-actions':
                del body['Actions']
            elif mode == 'vm-actions-by-state':
                if self.server.vm_inserted:
                    del body['Actions']['#VirtualMedia.InsertMedia']
                else:
                    del body['Actions']['#VirtualMedia.EjectMedia']
                    body['Actions']['#VirtualMedia.InsertMedia']['@Redfish.ActionInfo'] = VM_MEDIA + '/InsertMediaActionInfo'
            elif mode == 'vm-ibmc-shaped':
                body = {'@odata.type': '#VirtualMedia.v1_0_2.VirtualMedia', 'Id': 'CD', 'Name': 'VirtualMedia',
                        'MediaTypes': [], 'Image': None, 'ImageName': None, 'Inserted': False,
                        'ConnectedVia': 'NotConnected',
                        'Oem': {'Huawei': {'Actions': {
                            '#VirtualMedia.VmmControl': {'target': '/redfish/v1/Managers/1/VirtualMedia/CD/Oem/Huawei/Actions/VirtualMedia.VmmControl'}}}}}
        elif self.path == VM_MEDIA + '/InsertMediaActionInfo' and mode == 'vm-actions-by-state':
            body = {'@odata.type': '#ActionInfo.v1_1_2.ActionInfo', 'Parameters': [
                {'Name': 'Image', 'DataType': 'String', 'Required': True},
                {'Name': 'UserName', 'DataType': 'String', 'Required': False},
                {'Name': 'Password', 'DataType': 'String', 'Required': False},
            ]}
        elif self.path == IRMC_SYSTEM:
            action = 'DisconnectCD' if self.server.vm_inserted else 'ConnectCD' if self.server.vm_image else None
            body = {'@odata.type': '#ComputerSystem.v1_0_5.ComputerSystem',
                    'Oem': {'ts_fujitsu': {'VirtualMedia': {'@odata.id': IRMC_MEDIA}}},
                    'Actions': {'Oem': {IRMC_SCHEMA + 'FTSComputerSystem.VirtualMedia': {
                        'target': IRMC_ACTION, 'FTSVirtualMediaAction@Redfish.AllowableValues': [action] if action else []}}}}
        elif self.path == IRMC_MEDIA:
            body = {'@odata.type': IRMC_SCHEMA + 'FTSVirtualMedia.v1_1_0.FTSVirtualMedia',
                    '@odata.etag': 'irmc-fixture', 'RemoteMountEnabled': True,
                    'IsAnyVirtualMediaActive': self.server.vm_inserted,
                    'CDImage': {'MaximumNumberOfDevices': 2, 'ImageName': self.server.vm_image}}
        elif self.path == '/redfish/v1/Managers/mgr1':
            body = {'@odata.type': '#Manager.v1_15_0.Manager', 'Id': 'mgr1', 'Name': 'Manager',
                    'VirtualMedia': {'@odata.id': VM_COLLECTION},
                    'GraphicalConsole': {'ServiceEnabled': True, 'Port': 5900, 'MaxConcurrentSessions': 2,
                                         'ConnectTypesSupported': ['KVMIP', 'Oem']}}
            if mode == 'irmc-media':
                body['Links'] = {'ManagerForServers': [{'@odata.id': IRMC_SYSTEM}]}
                body['Oem'] = {'ts_fujitsu': {'iRMCConfiguration': {'@odata.id': '/redfish/v1/Managers/mgr1/Oem/ts_fujitsu/iRMCConfiguration'}}}
        elif self.path == MANAGERS:
            body = {'@odata.type': '#ManagerCollection.ManagerCollection', 'Members': [{'@odata.id': MANAGER}]}
            if mode == 'manager-duplicates':
                body['Members'].append({'@odata.id': MANAGER})
        elif self.path == MANAGER:
            body = {'@odata.type': '#Manager.v1_15_0.Manager', 'Id': 'bmc', 'Name': 'Baseboard manager',
                    'NetworkProtocol': {'@odata.id': NETWORK_PROTOCOL},
                    'EthernetInterfaces': {'@odata.id': ETH_COLLECTION}}
            if mode == 'missing-network-protocol':
                del body['NetworkProtocol']
            elif mode == 'external-network-protocol':
                body['NetworkProtocol']['@odata.id'] = 'https://different.invalid/NetworkProtocol'
            elif mode == 'missing-ethernet':
                del body['EthernetInterfaces']
            elif mode == 'external-ethernet':
                body['EthernetInterfaces']['@odata.id'] = 'https://different.invalid/EthernetInterfaces'
        elif self.path == NETWORK_PROTOCOL:
            body = {'@odata.type': '#ManagerNetworkProtocol.v1_7_0.ManagerNetworkProtocol',
                    'HostName': 'bmc-host', 'FQDN': 'bmc-host.example.com',
                    'NTP': {'ProtocolEnabled': True, 'Port': 123,
                            'NTPServers': ['10.0.0.1', 'ntp.example.com'],
                            'NetworkSuppliedServers': ['10.0.0.2']},
                    'SSH': {'ProtocolEnabled': True, 'Port': 22},
                    'SNMP': {'ProtocolEnabled': False},
                    'HTTP': {'ProtocolEnabled': True, 'Port': 80},
                    'HTTPS': {'ProtocolEnabled': True, 'Port': 443},
                    'IPMI': {'ProtocolEnabled': True, 'Port': 623},
                    'VirtualMedia': {'ProtocolEnabled': True, 'Port': 17988},
                    'KVMIP': {'ProtocolEnabled': False},
                    'SSDP': {'ProtocolEnabled': True, 'Port': 1900},
                    'Telnet': {'ProtocolEnabled': False}}
            if mode == 'network-null-snmp':
                body['SNMP'] = None
            elif mode == 'network-missing-telnet':
                del body['Telnet']
            elif mode == 'network-null-port':
                body['HTTP'] = {'ProtocolEnabled': False, 'Port': None}
            elif mode == 'network-zero-port':
                body['HTTP'] = {'ProtocolEnabled': False, 'Port': 0}
            elif mode == 'network-null-enabled':
                body['SSH'] = {'ProtocolEnabled': None, 'Port': 22}
            elif mode == 'network-null-hostname':
                body['HostName'] = None
            elif mode == 'network-bad-port':
                body['HTTP']['Port'] = '80'
            elif mode == 'network-bool-port':
                body['SSH']['Port'] = True
            elif mode == 'network-oversized-ntp':
                body['NTP']['NTPServers'] = ['10.0.0.%d' % i for i in range(1, 10)]
            elif mode == 'network-wrong-type':
                body['@odata.type'] = '#Manager.v1_0_0.Manager'
        elif self.path == ETH_COLLECTION or self.path.startswith(ETH_COLLECTION + '?'):
            second = '?page=2' in self.path
            members = [ETH1] if second else [ETH0]
            if mode == 'eth-duplicates' and second:
                members.insert(0, ETH0)
            body = {'@odata.type': '#EthernetInterfaceCollection.EthernetInterfaceCollection',
                    'Members': [{'@odata.id': value} for value in members]}
            if not second:
                body['Members@odata.nextLink'] = ETH_COLLECTION if mode == 'eth-cycle' else ETH_COLLECTION + '?page=2'
            if mode == 'eth-external-member':
                body['Members'][0]['@odata.id'] = 'https://different.invalid/eth'
            elif mode == 'eth-empty':
                body = {'@odata.type': '#EthernetInterfaceCollection.EthernetInterfaceCollection', 'Members': []}
        elif self.path == ETH0:
            body = {'@odata.type': '#EthernetInterface.v1_9_0.EthernetInterface', 'Id': 'eth0',
                    'Name': 'Management interface', 'MACAddress': 'aa:bb:cc:dd:ee:ff',
                    'Status': {'State': 'Enabled', 'Health': 'OK'},
                    'InterfaceEnabled': True, 'LinkStatus': 'LinkUp',
                    'DHCPv4': {'DHCPEnabled': True},
                    'DHCPv6': {'OperatingMode': 'Stateful', 'DHCPEnabled': False},
                    'HostName': 'bmc-host', 'FQDN': None,
                    'IPv4Addresses': [
                        {'Address': '192.168.1.10', 'SubnetMask': '255.255.255.0',
                         'Gateway': '192.168.1.1', 'AddressOrigin': 'DHCP'},
                        {'Address': '10.0.0.5', 'SubnetMask': None, 'Gateway': '0.0.0.0', 'AddressOrigin': 'Static'}],
                    'IPv6Addresses': [
                        {'Address': 'fe80::1', 'PrefixLength': 64, 'AddressOrigin': 'LinkLocal',
                         'AddressState': 'Preferred'},
                        {'Address': None, 'PrefixLength': None}]}
            if mode == 'eth-missing-mac':
                del body['MACAddress']
            elif mode == 'eth-null-mac':
                body['MACAddress'] = None
            elif mode == 'eth-null-status':
                body['Status'] = {'State': None, 'Health': None}
            elif mode == 'eth-missing-dhcp4':
                del body['DHCPv4']
            elif mode == 'eth-bool-dhcp':
                body['DHCPv4']['DHCPEnabled'] = 'yes'
            elif mode == 'eth-too-many-ipv4':
                body['IPv4Addresses'] *= 3
            elif mode == 'eth-bad-prefix':
                body['IPv6Addresses'][0]['PrefixLength'] = 129
            elif mode == 'eth-wrong-type':
                body['@odata.type'] = '#Manager.v1_0_0.Manager'
        elif self.path == ETH1:
            body = {'@odata.type': '#EthernetInterface.v1_9_0.EthernetInterface', 'Id': 'eth1',
                    'Status': {'State': 'Absent'}}
        elif self.path == VM_COLLECTION:
            body = {'@odata.type': '#VirtualMediaCollection.VirtualMediaCollection',
                    'Members': [] if mode == 'irmc-media' else [{'@odata.id': VM_MEDIA}]}
        elif self.path == SENSOR:
            if mode in ('sensor-not-implemented', 'sensor-forbidden'):
                self.reply(501 if mode == 'sensor-not-implemented' else 403, {'error': {'code': 'Base.1.0.GeneralError'}})
                return
            body = {'@odata.type': '#Sensor.v1_11_1.Sensor', 'Id': 'ambient', 'Name': 'Ambient temperature',
                    'Reading': 22.5, 'ReadingType': 'Temperature', 'ReadingUnits': 'Cel',
                    'ReadingRangeMin': -40, 'ReadingRangeMax': 150, 'ReadingTime': '2026-10-19T08:00:00Z',
                    'Status': {'State': 'Enabled', 'Health': 'OK'},
                    'Thresholds': {'LowerCritical': {'Reading': 0}, 'UpperCaution': {'Reading': 60, 'Activation': 'Increasing', 'DwellTime': 'PT10S'},
                                   'UpperCritical': {'Reading': None}, 'UpperCautionUser': {'Reading': 55}}}
            if mode.startswith('context-'):
                body.update(PhysicalContext='CPU', ReadingBasis='Zero', Enabled=True,
                            RelatedItem=[{'@odata.id': BASE + '/A/Processors/1'}, {'@odata.id': BASE + '/A/Processors/1'}],
                            Sensors={'@odata.id': SENSORS}, Thermal={'@odata.id': CHASSIS + '/Thermal'},
                            Links={'Chassis': [{'@odata.id': CHASSIS}], 'ComputerSystems': [{'@odata.id': BASE + '/A'}]})
                if mode == 'context-foreign': body['RelatedItem'][0]['@odata.id'] = 'https://other.invalid/redfish/v1/Systems/A'
                elif mode == 'context-fragment': body['RelatedItem'] = [{'@odata.id': BASE + '/A#/SomeObject/0'}]
                elif mode == 'context-wrong-type': body['PhysicalContext'] = 7
                elif mode == 'context-wrong-links': body['Links']['Chassis'] = 'invalid'
                elif mode == 'context-many': body['RelatedItem'] *= 129
                elif mode == 'context-headroom': body['ReadingBasis'] = 'Headroom'
                elif mode == 'context-disabled': body['Enabled'] = False
                elif mode == 'context-range': body['Reading'] = 200
                elif mode == 'context-null': body['PhysicalContext'] = body['ReadingBasis'] = body['Enabled'] = None
                elif mode == 'context-absent': body.pop('ReadingBasis'); body.pop('Enabled')
            if mode == 'sensor-zero':
                body['Reading'] = 0
            elif mode == 'sensor-negative':
                body['Reading'] = -12.75
            elif mode == 'sensor-null':
                body['Reading'] = body['ReadingType'] = body['ReadingUnits'] = body['ReadingTime'] = None
                body['Status']['Health'] = body['Status']['State'] = None
            elif mode == 'sensor-missing':
                del body['Reading']
            elif mode == 'sensor-string':
                body['Reading'] = '22.5'
            elif mode == 'sensor-bool':
                body['Reading'] = False
            elif mode == 'sensor-infinite':
                body['Reading'] = float('inf')
            elif mode == 'sensor-wrong-type':
                body['@odata.type'] = '#Thermal.v1_4_0.Thermal'
            elif mode == 'sensor-future':
                body['Status']['Health'] = 'FutureHealth'
                body['ReadingType'] = 'FutureReadingType'
                body['ReadingUnits'] = 'vendor-unit'
            elif mode == 'sensor-bad-threshold':
                body['Thresholds']['LowerFatal'] = {'Reading': 'cold'}
        elif self.path == INFO:
            body = {'@odata.type': '#ActionInfo.v1_1_2.ActionInfo', 'Parameters': [{'Name': 'ResetType', 'Required': True, 'DataType': 'String', 'AllowableValues': ['On', 'GracefulShutdown', 'FutureReset', None]}]}
            if mode == 'extra-required':
                body['Parameters'].append({'Name': 'VendorConfirmation', 'Required': True, 'DataType': 'String'})
            elif mode == 'duplicate-reset':
                body['Parameters'].append(body['Parameters'][0])
            elif mode == 'missing-values':
                del body['Parameters'][0]['AllowableValues']
        elif self.path.startswith(BASE) and '/host-' not in self.path:
            second = '?page=2' in self.path
            names = ['host-B'] if second else ['host-A']
            if mode == 'duplicates' and second:
                names.insert(0, 'host-A')
            body = {'@odata.type': '#ComputerSystemCollection.ComputerSystemCollection', 'Members': [{'@odata.id': BASE + '/' + n} for n in names]}
            if mode == 'external':
                body['Members'][0]['@odata.id'] = 'https://different.invalid/system'
            if mode == 'cycle' or not second:
                body['Members@odata.nextLink'] = self.path if mode == 'cycle' else BASE + '?page=2'
        elif self.path.startswith(BASE + '/host-'):
            body = {'@odata.type': '#ComputerSystem.v1_22_0.ComputerSystem', 'Id': 'host-A', 'Name': 'Fixture system', 'PowerState': self.server.power}
            body.update(Manufacturer='FixtureVendor', Model='FixtureModel', SerialNumber='fixture-serial',
                        UUID='fixture-uuid', HostName='fixture-host')
            if mode == 'identity-null':
                for key in ('Manufacturer', 'Model', 'SerialNumber', 'UUID', 'HostName'):
                    body[key] = None
            elif mode == 'identity-invalid':
                body['Manufacturer'] = 42
            body['Boot'] = dict(self.server.boot)
            body['@odata.etag'] = 'W/"fixture-boot"'
            if mode == 'boot-no-targets':
                del body['Boot']['BootSourceOverrideTarget@Redfish.AllowableValues']
            elif mode == 'boot-no-once':
                body['Boot']['BootSourceOverrideEnabled@Redfish.AllowableValues'] = ['Disabled', 'Continuous']
            elif mode == 'boot-malformed':
                body['Boot']['BootSourceOverrideTarget@Redfish.AllowableValues'] = 'Cd'
            elif mode == 'boot-none':
                del body['Boot']
            body['Actions'] = {'#ComputerSystem.Reset': {'target': TARGET, '@Redfish.ActionInfo': INFO}}
            action = body['Actions']['#ComputerSystem.Reset']
            if mode == 'inline':
                del action['@Redfish.ActionInfo']
                action['ResetType@Redfish.AllowableValues'] = ['On', 'GracefulShutdown']
            elif mode == 'conflict':
                action['ResetType@Redfish.AllowableValues'] = ['ForceOff']
            elif mode == 'no-action':
                del body['Actions']
            elif mode == 'bad-target':
                action['target'] = '/redfish/v1/../../admin'
            elif mode == 'external-target':
                action['target'] = 'https://other.invalid/Reset'
            if mode == 'unknown':
                body['PowerState'] = 'FuturePowerState'
            if mode == 'no-power':
                del body['PowerState']
            if mode == 'null-power':
                body['PowerState'] = None
            if mode == 'wrong-type':
                body['@odata.type'] = '#Manager.v1_0_0.Manager'
            if mode == 'http-error':
                status, body = 503, {'error': {'code': 'Base.1.0.ServiceTemporarilyUnavailable'}}
        else:
            status, body = 404, {'error': {'code': 'Base.1.0.ResourceMissingAtURI'}}
        self.reply(status, body)

    def reply(self, status, body, headers=()):
        encoded = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        trailers = self.server.mode == 'trailers' and self.path == MONITOR
        if trailers:
            self.send_header('Transfer-Encoding', 'chunked')
            self.send_header('Trailer', 'Location')
        else:
            self.send_header('Content-Length', str(len(encoded)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        if trailers:
            self.wfile.write(f'{len(encoded):x}\r\n'.encode() + encoded + b'\r\n0\r\nLocation: https://ignored.invalid/trailer\r\n\r\n')
        else:
            self.wfile.write(encoded)

    def do_PATCH(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        self.server.posts.append((self.path, body))
        if self.path == IRMC_MEDIA:
            assert self.headers.get('If-Match') == 'irmc-fixture'
            self.server.vm_image = body['CDImage']['ImageName']
            self.reply(204, b'')
            return
        assert self.path == BASE + '/host-A'
        assert set(body) == {'Boot'}
        assert 'BootOrder' not in body['Boot']
        assert self.headers.get('If-Match') == 'W/"fixture-boot"'
        if self.server.mode != 'boot-mismatch':
            self.server.boot.update(body['Boot'])
        if self.server.mode == 'boot-accepted':
            self.reply(202, b'', [('Location', MONITOR)])
        else:
            self.reply(204, b'')

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        body = json.loads(raw) if raw else None
        self.server.posts.append((self.path, body))
        if self.path == IRMC_ACTION:
            self.server.vm_inserted = body['FTSVirtualMediaAction'] == 'ConnectCD'
            self.reply(204, b'')
            return
        if self.path in (VM_INSERT, VM_EJECT) and self.server.mode in ('vm-drop', 'vm-reject'):
            if self.server.mode == 'vm-reject':
                self.reply(403, {'error': {'code': 'Base.1.0.InsufficientPrivilege'}})
            else:
                self.server.vm_inserted = self.path == VM_INSERT
                self.server.vm_image = body['Image'] if self.server.vm_inserted else ''
                self.connection.shutdown(socket.SHUT_RDWR)
                self.close_connection = True
            return
        if self.path in (VM_INSERT, VM_EJECT) and self.server.mode.startswith('vm-accepted'):
            target = 'https://different.invalid/monitor' if self.server.mode == 'vm-accepted-foreign' else MONITOR
            task = {'@odata.type': '#Task.v1_7_0.Task', '@odata.id': TASK, 'TaskState': 'Running'}
            if self.server.mode == 'vm-accepted-empty': task = b''
            self.reply(202, task, [('Location', target), ('Retry-After', '2')])
            return
        if self.path == VM_INSERT:
            self.server.vm_inserted, self.server.vm_image = True, body['Image']
            self.reply(204, b'')
            return
        if self.path == VM_EJECT:
            self.server.vm_inserted, self.server.vm_image = False, ''
            self.reply(204, b'')
            return
        if self.path != TARGET or body != {'ResetType': 'On'}:
            self.reply(400, {'error': {'code': 'Base.1.0.ActionParameterNotSupported'}})
            return
        mode = self.server.mode
        if mode == 'reject':
            self.reply(403, {'error': {'code': 'Base.1.0.InsufficientPrivilege'}})
        elif mode == 'drop':
            self.server.power = 'On'
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
        elif mode == 'bad-success':
            self.reply(200, b'{broken')
        elif mode == 'body-error':
            self.reply(200, {'error': {'code': 'Base.1.0.GeneralError'}})
        elif mode in ('accepted', 'accepted-external', 'accepted-no-body'):
            target = 'https://different.invalid/monitor' if mode == 'accepted-external' else MONITOR
            self.reply(202, b'' if mode == 'accepted-no-body' else self.task(), [('Location', target), ('Retry-After', '2')])
        elif mode == 'success-message':
            self.server.power = 'On'
            self.reply(200, {'@Message.ExtendedInfo': [{'MessageId': 'Base.1.0.Success'}]})
        else:
            self.server.power = 'On'
            self.reply(204, b'')


class Redfish(unittest.TestCase):
    def test_sensor_details_unsupported_is_not_permission_failure(self):
        for mode, expected in [('sensor-not-implemented', 'unsupported'), ('sensor-forbidden', 'http_error'), ('sensor-wrong-type', 'protocol_error')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'sensor-details', SENSOR)
                self.assertEqual(row['sensor_details']['status'], expected)
                self.assertIsNone(row['sensor_details']['reading'])

    def test_sensor_details_partial_fields_and_unknown_health(self):
        for mode in ('normal', 'sensor-bad-threshold', 'sensor-bool', 'sensor-null', 'sensor-missing', 'sensor-future'):
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'sensor-details', SENSOR)
                details = row['sensor_details']
                self.assertEqual(details['fields']['states']['state'], 'unsupported')
                if mode == 'sensor-bad-threshold':
                    self.assertEqual(details['reading'], 22.5)
                    self.assertEqual(details['status'], 'protocol_error')
                    self.assertEqual(details['thresholds'][2]['state'], 'error')
                    self.assertEqual(details['thresholds'][3]['reading'], 60)
                elif mode == 'sensor-bool':
                    self.assertEqual(details['fields']['reading']['state'], 'error')
                    self.assertEqual(details['health'], 1)
                    self.assertEqual(details['thresholds'][3]['reading'], 60)
                elif mode == 'sensor-null':
                    self.assertEqual(details['fields']['reading']['state'], 'unavailable')
                    self.assertEqual(details['fields']['health']['state'], 'unavailable')
                elif mode == 'sensor-missing':
                    self.assertEqual(details['fields']['reading']['state'], 'not_reported')
                elif mode == 'sensor-future':
                    self.assertEqual(details['health'], 0)
                    self.assertEqual(details['health_text'], 'FutureHealth')
                else:
                    self.assertEqual(details['reading'], 22.5)
                    self.assertEqual(details['thresholds'][1]['reading'], 0)

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='bcontrol-redfish-')
        cls.root = Path(cls.temp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.root / 'key'), '-out', str(cls.root / 'cert'), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def fixture(self, mode='normal'):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        server.mode, server.requests = mode, []
        server.posts, server.power = [], 'PoweringOff'
        server.boot = {'BootSourceOverrideEnabled': 'Disabled', 'BootSourceOverrideTarget': 'None',
                       'BootSourceOverrideMode': 'UEFI', 'BootSourceOverrideTarget@Redfish.AllowableValues': ['None', 'Cd', 'Pxe', 'Hdd', 'FutureVendor'],
                       'BootSourceOverrideEnabled@Redfish.AllowableValues': ['Disabled', 'Once', 'Continuous']}

        server.vm_inserted, server.vm_image = False, ''
        server.task_state, server.monitor_gone = 'Running', False
        server.auth_seen = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / 'cert', self.root / 'key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def call(self, server, action='discover', uri='', maximum='0'):
        result = subprocess.run([CLIENT, 'https://localhost:' + str(server.server_port), str(self.root / 'cert'), action, uri, maximum], capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = json.loads(result.stdout)
        self.assertEqual(row['completion_count'], 1)
        return row

    def test_discovery_follows_links_pages_and_deduplicates(self):
        for mode in ('normal', 'duplicates'):
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server)
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(row['systems'], [BASE + '/host-A', BASE + '/host-B'])
                self.assertEqual(row['redfish_version'], '1.17.0')
                self.assertEqual(server.requests, ['/redfish/v1/', BASE, BASE + '?page=2'])

    def test_system_states_and_optional_properties(self):
        for mode, state, raw in [('normal', 4, 'PoweringOff'), ('unknown', 0, 'FuturePowerState'), ('no-power', 0, ''), ('null-power', 0, '')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'system', BASE + '/host-A')
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(row['power_state'], state)
                self.assertEqual(row['raw_power_state'], raw)
                self.assertEqual(row['id'], 'host-A')

    def test_system_identity_optional_and_invalid_fields(self):
        with self.fixture() as server:
            row = self.call(server, 'system', BASE + '/host-A')
            self.assertEqual((row['manufacturer'], row['model'], row['serial_number'], row['uuid'], row['host_name']),
                             ('FixtureVendor', 'FixtureModel', 'fixture-serial', 'fixture-uuid', 'fixture-host'))
        with self.fixture('identity-null') as server:
            row = self.call(server, 'system', BASE + '/host-A')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['manufacturer'], '')
        with self.fixture('identity-invalid') as server:
            self.assertEqual(self.call(server, 'system', BASE + '/host-A')['status'], 'protocol_error')

    def test_errors_loops_limits_and_unsupported_links(self):
        for mode, expected in [('cycle', 'protocol_error'), ('external', 'unsupported'), ('malformed', 'protocol_error'), ('bad-version', 'protocol_error'), ('error', 'redfish_error'), ('missing', 'unsupported')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server)
                self.assertEqual(row['status'], expected)
                self.assertLessEqual(len(server.requests), 2)
                if mode in ('error', 'malformed'):
                    self.assertGreater(row['error_body_length'], 0)
        with self.fixture() as server:
            self.assertEqual(self.call(server, maximum='1')['status'], 'limit_exceeded')
        with self.fixture('wrong-type') as server:
            self.assertEqual(self.call(server, 'system', BASE + '/host-A')['status'], 'protocol_error')
        with self.fixture('http-error') as server:
            row = self.call(server, 'system', BASE + '/host-A')
            self.assertEqual(row['status'], 'http_error')
            self.assertEqual(row['http_status'], 503)
            self.assertGreater(row['error_body_length'], 0)

    def test_cancellation_delivers_once_and_releases_resources(self):
        with self.fixture() as server:
            self.assertEqual(self.call(server, 'cancel')['status'], 'cancelled')
            self.assertEqual(server.requests, [])

    def test_boot_override_preflight_and_patch(self):
        with self.fixture() as server:
            row = self.call(server, 'boot', BASE + '/host-A')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['boot_targets'], 15)
            row = self.call(server, 'boot-cd', BASE + '/host-A')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['flags'] & 4, 4)
            self.assertEqual(server.posts, [(BASE + '/host-A', {'Boot': {'BootSourceOverrideEnabled': 'Once', 'BootSourceOverrideTarget': 'Cd'}})])
            readback = self.call(server, 'boot', BASE + '/host-A')
            self.assertEqual(readback['boot_target'], 3)
            self.assertEqual(readback['boot_flags'] & 3, 1)
            self.call(server, 'boot-disable', BASE + '/host-A')
            self.assertEqual(server.boot['BootSourceOverrideEnabled'], 'Disabled')
            self.assertEqual(server.power, 'PoweringOff')
        with self.fixture('boot-mismatch') as server:
            self.assertEqual(self.call(server, 'boot-cd', BASE + '/host-A')['status'], 'outcome_unknown')
            self.assertEqual(len(server.posts), 1)
        with self.fixture('boot-accepted') as server:
            row = self.call(server, 'boot-cd', BASE + '/host-A')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['flags'] & 5, 1)
            self.assertEqual(row['task']['monitor_uri'], MONITOR)
        for mode, expected in [('boot-no-targets', 'unsupported'), ('boot-no-once', 'unsupported'),
                               ('boot-malformed', 'protocol_error'), ('boot-none', 'unsupported')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'boot-cd', BASE + '/host-A')['status'], expected)
                self.assertEqual(server.posts, [])

    def test_reset_capabilities_and_stateful_power_control(self):
        for mode in ('normal', 'inline', 'conflict', 'success-message'):
            with self.subTest(mode=mode), self.fixture(mode) as server:
                caps = self.call(server, 'capabilities', BASE + '/host-A')
                self.assertEqual(caps['status'], 'ok')
                self.assertEqual(caps['supported_reset_types'], (1 << 0) | (1 << 2))
                self.assertEqual(caps['reset_target'], TARGET)
                self.assertEqual(server.posts, [])
                row = self.call(server, 'reset', BASE + '/host-A')
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(row['flags'], 1)
                self.assertEqual(row['power_state'], 0)
                self.assertEqual(server.posts, [(TARGET, {'ResetType': 'On'})])
                self.assertEqual(self.call(server, 'system', BASE + '/host-A')['power_state'], 1)
                self.assertEqual(server.requests.count(INFO), 0 if mode == 'inline' else 2)

    def test_reset_rejects_unsupported_and_malformed_capabilities_without_post(self):
        for mode, action, expected in [('normal', 'reset-off', 'unsupported'), ('no-action', 'reset', 'unsupported'), ('missing-values', 'reset', 'unsupported'), ('extra-required', 'reset', 'unsupported'), ('duplicate-reset', 'reset', 'protocol_error'), ('bad-target', 'reset', 'unsupported'), ('external-target', 'reset', 'unsupported')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, action, BASE + '/host-A')['status'], expected)
                self.assertEqual(server.posts, [])

    def test_reset_response_loss_rejection_and_async_acceptance(self):
        for mode, expected, flags in [('drop', 'outcome_unknown', 0), ('reject', 'http_error', 0), ('bad-success', 'outcome_unknown', 0), ('body-error', 'redfish_error', 0), ('accepted', 'ok', 3)]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'reset', BASE + '/host-A')
                self.assertEqual(row['status'], expected)
                self.assertEqual(row['flags'], flags)
                self.assertEqual(server.posts, [(TARGET, {'ResetType': 'On'})])

    def test_accepted_reset_exposes_links_and_monitor_lifecycle(self):
        with self.fixture('accepted') as server:
            row = self.call(server, 'reset', BASE + '/host-A')
            task = row['task']
            self.assertEqual((task['task_uri'], task['monitor_uri'], task['retry_after']), (TASK, MONITOR, '2'))
            self.assertEqual(server.requests, [BASE + '/host-A', INFO])
            first = self.call(server, 'monitor', task['monitor_uri'])
            self.assertEqual(first['status'], 'ok')
            self.assertEqual(first['http_status'], 202)
            self.assertEqual(first['task']['flags'], 1 | 32)
            self.assertEqual(first['task']['percent_complete'], 33)
            self.assertEqual(json.loads(first['task']['messages_json'])[0]['Message'], 'Started')
            server.task_state = 'Exception'
            final = self.call(server, 'monitor', MONITOR)
            self.assertEqual(final['http_status'], 204)
            self.assertEqual(final['task']['flags'], 2)
            resource = self.call(server, 'task', TASK)
            self.assertEqual(resource['status'], 'ok')
            self.assertEqual(resource['task']['state'], 'Exception')
            self.assertEqual(resource['task']['flags'], 4 | 8 | 32)
            gone = self.call(server, 'monitor', MONITOR)
            self.assertEqual(gone['status'], 'http_error')
            self.assertEqual(gone['http_status'], 404)
            self.assertEqual(gone['task']['flags'], 0)
            self.assertEqual(len(server.posts), 1)

    def test_task_state_unknown_interruptions_cancelled_and_nullable_percent(self):
        for state, flags in [('Completed', 4), ('Interrupted', 0), ('FutureState', 0), ('Cancelled', 4 | 16)]:
            with self.subTest(state=state), self.fixture() as server:
                server.task_state = state
                row = self.call(server, 'task', TASK)
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(row['task']['state'], state)
                self.assertEqual(row['task']['flags'], flags | 32)
        with self.fixture('null-percent') as server:
            self.assertEqual(self.call(server, 'task', TASK)['task']['flags'], 0)
        with self.fixture('bad-percent') as server:
            self.assertEqual(self.call(server, 'task', TASK)['status'], 'protocol_error')
        with self.fixture() as server:
            self.assertEqual(self.call(server, 'monitor-cancel', MONITOR)['status'], 'cancelled')
            self.assertEqual(server.requests, [])
            self.assertEqual(server.posts, [])

    def test_monitor_final_result_preserves_original_operation_response(self):
        for mode, expected in [('monitor-final-error', 'redfish_error'), ('monitor-final-created', 'ok'), ('monitor-final-bytes', 'ok')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'monitor', MONITOR)
                self.assertEqual(row['status'], expected)
                self.assertEqual(row['task']['flags'], 2)
                self.assertGreater(row['task']['final_body_length'], 0)

    def test_response_header_boundaries_and_unfollowed_cross_origin(self):
        for mode, expected in [('duplicate-header', 'protocol_error'), ('duplicate-token', 'protocol_error'), ('bad-token-header', 'protocol_error'), ('oversized-location', 'protocol_error'), ('header-budget', 'limit_exceeded'), ('external-monitor', 'unsupported'), ('interim', 'ok'), ('trailers', 'ok'), ('retry-date', 'ok')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'monitor', MONITOR)
                self.assertEqual(row['status'], expected)
                self.assertEqual(server.requests, [MONITOR])
                if expected == 'ok':
                    self.assertEqual(row['task']['monitor_uri'], MONITOR)
                if mode == 'retry-date':
                    self.assertEqual(row['task']['retry_after'], 'Wed, 21 Oct 2026 07:28:00 GMT')
        for mode, expected in [('accepted-external', 'unsupported'), ('accepted-no-body', 'ok')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'reset', BASE + '/host-A')
                self.assertEqual(row['status'], expected)
                self.assertEqual(row['flags'], 3)
                self.assertEqual(len(server.posts), 1)
                if expected == 'ok':
                    self.assertEqual(row['task']['monitor_uri'], MONITOR)

    def test_sensor_numeric_reading_units_status_and_thresholds(self):
        for mode, reading in [('normal', 22.5), ('sensor-zero', 0), ('sensor-negative', -12.75)]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'sensor', SENSOR)
                self.assertEqual(row['status'], 'ok')
                sensor = row['sensor']
                self.assertEqual(sensor['reading'], reading)
                self.assertEqual(sensor['flags'], 7)
                self.assertEqual((sensor['units'], sensor['reading_type'], sensor['health']), ('Cel', 'Temperature', 'OK'))
                self.assertEqual((sensor['range_min'], sensor['range_max']), (-40, 150))
                self.assertEqual(sensor['threshold_mask'], (1 << 1) | (1 << 3))
                self.assertEqual(sensor['thresholds'], [None, 0, None, 60, None, None])
                raw = json.loads(sensor['thresholds_json'])
                self.assertEqual(raw['UpperCaution']['DwellTime'], 'PT10S')
                self.assertEqual(raw['UpperCautionUser']['Reading'], 55)
                self.assertEqual(server.requests, [SENSOR])

    def test_sensor_nullable_unknown_and_invalid_values(self):
        for mode in ('sensor-null', 'sensor-missing'):
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'sensor', SENSOR)
                self.assertEqual(row['status'], 'ok')
                self.assertIsNone(row['sensor']['reading'])
                self.assertEqual(row['sensor']['flags'], 6)
        with self.fixture('sensor-future') as server:
            sensor = self.call(server, 'sensor', SENSOR)['sensor']
            self.assertEqual((sensor['health'], sensor['reading_type'], sensor['units']), ('FutureHealth', 'FutureReadingType', 'vendor-unit'))
        for mode in ('sensor-string', 'sensor-bool', 'sensor-infinite', 'sensor-wrong-type', 'sensor-bad-threshold'):
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'sensor', SENSOR)['status'], 'protocol_error')

    def test_sensor_context_is_owned_bounded_and_independent_of_reading(self):
        with self.fixture('context-normal') as server:
            row = self.call(server, 'sensor', SENSOR)
            self.assertEqual(row['status'], 'ok')
            context = row['context']
            self.assertEqual((context['physical_context'], context['reading_basis'], context['enabled'], context['flags']), ('CPU', 'Zero', 1, 3))
            self.assertEqual(context['related_items'], [BASE + '/A/Processors/1'])
            self.assertEqual(context['chassis'], [CHASSIS])
            self.assertEqual(context['sensor_collection_uri'], SENSORS)
            self.assertEqual(context['thermal_uri'], CHASSIS + '/Thermal')
            self.assertEqual(row['temperature'], {'status': 'ok', 'flags': 23, 'unit': 1})
            self.assertEqual(context['systems'], [BASE + '/A'])
        for mode, status in [('context-foreign', 'unsupported'), ('context-wrong-type', 'protocol_error'),
                             ('context-wrong-links', 'protocol_error'), ('context-many', 'limit_exceeded')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'sensor', SENSOR)
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(row['sensor']['reading'], 22.5)
                self.assertEqual(row['context']['status'], status)
                self.assertEqual(row['context']['related_items'], [])
        for mode in ('context-headroom', 'context-disabled', 'context-range'):
            with self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'sensor', SENSOR)['temperature']['status'], 'unsupported')
        with self.fixture('context-fragment') as server:
            self.assertEqual(self.call(server, 'sensor', SENSOR)['context']['related_items'], [BASE + '/A#/SomeObject/0'])
        for mode, flags in [('context-null', 3), ('context-absent', 0)]:
            with self.fixture(mode) as server:
                context = self.call(server, 'sensor', SENSOR)['context']
                self.assertEqual((context['status'], context['flags'], context['reading_basis']), ('ok', flags, ''))

    def test_chassis_subresources_are_not_system_links(self):
        for mode, expected in [
            ('chassis-subresource-links', []),
            ('chassis-mixed-links', [BASE + '/A', CHASSIS + '/Oem/Systems/A', CHASSIS + '-other/Oem/Systems/A']),
        ]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                context = self.call(server, 'resource', CHASSIS)['context']
                self.assertEqual((context['status'], context['flags'], context['systems']), ('ok', 4, expected))
                self.assertEqual(context['sensor_collection_uri'], SENSORS)

    def test_chassis_and_sensor_discovery_follow_resource_relationships(self):
        for mode in ('normal', 'sensor-duplicates'):
            with self.subTest(mode=mode), self.fixture(mode) as server:
                chassis = self.call(server, 'chassis')
                self.assertEqual(chassis['status'], 'ok')
                self.assertEqual(chassis['collection'], {'kind': 1, 'members': [CHASSIS]})
                self.assertEqual(chassis['systems'], [])
                sensors = self.call(server, 'sensors', chassis['collection']['members'][0])
                self.assertEqual(sensors['status'], 'ok')
                self.assertEqual(sensors['collection'], {'kind': 2, 'members': [SENSOR, SENSORS + '/voltage']})
                self.assertEqual(sensors['resource_uri'], SENSORS)
                self.assertEqual(self.call(server, 'sensor', sensors['collection']['members'][0])['sensor']['reading'], 22.5)
                self.assertEqual(server.requests, ['/redfish/v1/', CHASSIS_COLLECTION, CHASSIS, SENSORS, SENSORS + '?page=2', SENSOR])

    def test_task_discovery_follows_relationships_and_gates_missing_services(self):
        with self.fixture() as server:
            row = self.call(server, 'tasks')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['collection'], {'kind': 3, 'members': [TASK]})
            self.assertEqual(server.requests, ['/redfish/v1/', '/redfish/v1/work-queue', '/redfish/v1/TaskService/Tasks'])
        with self.fixture('empty-tasks') as server:
            self.assertEqual(self.call(server, 'tasks')['collection']['members'], [])
        with self.fixture('task-pages') as server:
            row = self.call(server, 'tasks')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['collection']['members'], [TASK, TASK + '-next'])
        with self.fixture('task-pages') as server:
            row = self.call(server, 'tasks', maximum='1')
            self.assertEqual(row['status'], 'limit_exceeded')
            self.assertEqual(row['collection']['members'], [TASK])
        with self.fixture('task-cycle') as server:
            self.assertEqual(self.call(server, 'tasks')['status'], 'protocol_error')
        for mode, expected in [('missing-task-service', 'unsupported'), ('external-task-service', 'unsupported'),
                               ('missing-tasks', 'unsupported'), ('external-tasks', 'unsupported'),
                               ('wrong-task-service', 'protocol_error')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'tasks')['status'], expected)
                self.assertLessEqual(len(server.requests), 2)

    def test_collection_read_empty_members_and_partial_result_limits(self):
        for action, uri, kind in [('collection-sensors', SENSORS, 2), ('collection-chassis', CHASSIS_COLLECTION, 1), ('collection-systems', BASE, 0), ('collection-tasks', '/redfish/v1/TaskService/Tasks', 3)]:
            with self.subTest(action=action), self.fixture() as server:
                row = self.call(server, action, uri)
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(row['collection']['kind'], kind)
                self.assertEqual(server.requests[0], uri)
        with self.fixture('empty-sensors') as server:
            row = self.call(server, 'sensors', CHASSIS)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['collection']['members'], [])
        with self.fixture() as server:
            row = self.call(server, 'sensors', CHASSIS, maximum='1')
            self.assertEqual(row['status'], 'limit_exceeded')
            self.assertEqual(row['collection']['members'], [SENSOR])

    def test_sensor_discovery_rejects_cycles_missing_capability_and_external_links(self):
        for mode, expected in [('sensor-cycle', 'protocol_error'), ('sensor-wrong-collection', 'protocol_error'), ('missing-sensors', 'unsupported'), ('external-sensors', 'unsupported'), ('sensor-external-member', 'unsupported')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'sensors', CHASSIS)
                self.assertEqual(row['status'], expected)
                self.assertLessEqual(len(server.requests), 2)
        with self.fixture('missing-chassis') as server:
            self.assertEqual(self.call(server, 'chassis')['status'], 'unsupported')
        with self.fixture('sensor-cycle') as server:
            self.assertEqual(self.call(server, 'collection-sensors', SENSORS)['status'], 'protocol_error')
            self.assertEqual(server.requests, [SENSORS])
        with self.fixture() as server:
            self.assertEqual(self.call(server, 'sensors-cancel', CHASSIS)['status'], 'cancelled')
            self.assertEqual(server.requests, [])

    def test_auth_modes_keep_endpoint_credentials_and_connections_isolated(self):
        with self.fixture('auth-isolation') as server:
            env = {**os.environ, 'BC_BMC_USERNAME': 'fixture-user', 'BC_BMC_PASSWORD': 'fixture-password', 'BC_BMC_TOKEN': 'fixture-token'}
            process = subprocess.run([CLIENT, 'https://localhost:' + str(server.server_port), str(self.root / 'cert'), 'auth-isolation'], env=env, capture_output=True, text=True, timeout=8)
            self.assertEqual(process.returncode, 0, process.stderr)
            row = json.loads(process.stdout)
            self.assertEqual(row['completion_count'], 3)
            self.assertEqual(row['http_statuses'], [200, 200, 401])
            self.assertTrue(row['isolated_revisions'])
            self.assertEqual(row['response_tokens'], [False, True, False])
            self.assertCountEqual(server.auth_seen, ['basic', 'token', 'anonymous'])

    def test_graphical_console_capabilities(self):
        with self.fixture() as server:
            row = self.call(server, 'graphical-console', '/redfish/v1/Managers/mgr1')
            self.assertEqual(row['status'], 'ok')
            console = row['graphical_console']
            self.assertEqual((console['service_enabled'], console['port'], console['max_sessions']), (True, 5900, 2))
            self.assertEqual(console['connect_types'], ['KVMIP', 'Oem'])

    def test_virtual_media_discovery_from_manager(self):
        with self.fixture() as server:
            row = self.call(server, 'virtual-media-discover', '/redfish/v1/Managers/mgr1')
            self.assertEqual(row['status'], 'ok')
            collection = row['collection']
            self.assertEqual(len(collection['members']), 1)
            self.assertEqual(collection['members'][0], VM_MEDIA)

    def test_irmc_virtual_media_fallback_and_actions(self):
        with self.fixture('irmc-media') as server:
            result = self.call(server, 'virtual-media-discover', '/redfish/v1/Managers/mgr1')
            self.assertEqual(result['collection']['members'], [IRMC_MEDIA])
            self.assertEqual(self.call(server, 'virtual-media', IRMC_MEDIA)['virtual_media']['flags'] & 17, 16)
            self.assertEqual(self.call(server, 'vm-insert', IRMC_MEDIA)['status'], 'ok')
            self.assertEqual(server.posts, [
                (IRMC_MEDIA, {'CDImage': {'Server': 'fixture.invalid', 'ShareType': 'HTTP', 'ShareName': '/',
                                         'ImageName': 'image.iso', 'UserName': '', 'Password': '', 'UserDomain': ''}}),
                (IRMC_ACTION, {'FTSVirtualMediaAction': 'ConnectCD'}),
            ])
            self.assertEqual(self.call(server, 'virtual-media', IRMC_MEDIA)['virtual_media']['flags'] & 17, 17)
            self.assertEqual(self.call(server, 'vm-insert', IRMC_MEDIA)['status'], 'confirmation_required')
            self.assertEqual(len(server.posts), 2)
            self.assertEqual(self.call(server, 'vm-eject', IRMC_MEDIA)['status'], 'ok')
            self.assertEqual(server.posts[-1], (IRMC_ACTION, {'FTSVirtualMediaAction': 'DisconnectCD'}))
            self.assertEqual(self.call(server, 'virtual-media', IRMC_MEDIA)['virtual_media']['flags'] & 17, 16)

    def test_virtual_media_nullable_state(self):
        for mode in ['vm-null-state', 'vm-missing-state']:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'virtual-media', VM_MEDIA)
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(row['virtual_media']['id'], 'cd')
                self.assertEqual(row['virtual_media']['flags'] & 16, 0)
                self.assertEqual(server.posts, [])
                row = self.call(server, 'vm-insert', VM_MEDIA)
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(len(server.posts), 1)

    def test_virtual_media_insert_refuses_occupied_slot_without_posting(self):
        for mode, inserted, image in [('normal', True, ''),
                                       ('normal', False, 'http://fixture.invalid/existing.iso'),
                                       ('vm-missing-state', False, 'http://fixture.invalid/existing.iso')]:
            with self.subTest(mode=mode, inserted=inserted), self.fixture(mode) as server:
                server.vm_inserted, server.vm_image = inserted, image
                row = self.call(server, 'vm-insert', VM_MEDIA)
                self.assertEqual(row['status'], 'confirmation_required')
                self.assertEqual(row['flags'] & 12, 0)
                self.assertEqual(server.posts, [])
                row = self.call(server, 'vm-eject', VM_MEDIA)
                self.assertEqual(row['status'], 'ok')
                self.assertEqual(server.posts, [(VM_EJECT, {})])

    def test_virtual_media_failed_write_distinguishes_unknown_from_rejected(self):
        for action in ('vm-insert', 'vm-eject'):
            for mode in ('vm-drop', 'vm-reject'):
                with self.subTest(action=action, mode=mode), self.fixture(mode) as server:
                    row = self.call(server, action, VM_MEDIA)
                    self.assertNotEqual(row['status'], 'ok')
                    self.assertEqual(len(server.posts), 1)
                    self.assertEqual(row['flags'] & 4, 4)
                    self.assertEqual(row['flags'] & 8, 8 if mode == 'vm-drop' else 0)
                    self.assertEqual(row['http_status'], 0 if mode == 'vm-drop' else 403)
        with self.fixture('vm-no-actions') as server:
            row = self.call(server, 'vm-insert', VM_MEDIA)
            self.assertEqual(row['flags'] & 12, 0)
            self.assertEqual(server.posts, [])

    def test_virtual_media_async_retains_task_metadata_without_replaying_write(self):
        for action in ('vm-insert', 'vm-eject'):
            for mode in ('vm-accepted', 'vm-accepted-empty', 'vm-accepted-foreign'):
                with self.subTest(action=action, mode=mode), self.fixture(mode) as server:
                    row = self.call(server, action, VM_MEDIA)
                    self.assertEqual(len(server.posts), 1)
                    self.assertFalse(server.vm_inserted)
                    self.assertEqual(row['http_status'], 202)
                    self.assertEqual(row['flags'] & 3, 3)
                    if mode == 'vm-accepted-foreign':
                        self.assertEqual(row['status'], 'unsupported')
                    else:
                        self.assertEqual(row['status'], 'ok')
                        self.assertEqual(row['task']['monitor_uri'], MONITOR)
                        self.assertEqual(row['task']['retry_after'], '2')
                        if mode == 'vm-accepted':
                            self.assertEqual(row['task']['task_uri'], TASK)
                            self.assertEqual(row['task']['state'], 'Running')

    def test_virtual_media_actions_advertised_by_slot_state(self):
        with self.fixture('vm-actions-by-state') as server:
            empty = self.call(server, 'virtual-media', VM_MEDIA)
            self.assertEqual((empty['status'], empty['virtual_media']['flags'] & 12), ('ok', 4))
            self.assertEqual(self.call(server, 'vm-eject', VM_MEDIA)['status'], 'unsupported')
            self.assertEqual(server.posts, [])
            self.assertEqual(self.call(server, 'vm-insert', VM_MEDIA)['status'], 'ok')
            self.assertEqual(server.posts, [(VM_INSERT, {'Image': 'http://fixture.invalid/image.iso'})])
            mounted = self.call(server, 'virtual-media', VM_MEDIA)
            self.assertEqual((mounted['status'], mounted['virtual_media']['flags'] & 13), ('ok', 9))
            self.assertEqual(self.call(server, 'vm-eject', VM_MEDIA)['status'], 'ok')
            self.assertEqual(server.posts[-1], (VM_EJECT, {}))
            self.assertFalse(server.vm_inserted)

    def test_virtual_media_read_insert_eject_and_capability_gating(self):
        with self.fixture() as server:
            row = self.call(server, 'virtual-media', VM_MEDIA)
            self.assertEqual(row['status'], 'ok')
            media = row['virtual_media']
            self.assertEqual(media['id'], 'cd')
            self.assertTrue(media['flags'] & 16)
            self.assertTrue(media['flags'] & 12)
            self.assertEqual(media['insert_target'], VM_INSERT)
            row = self.call(server, 'vm-insert', VM_MEDIA)
            self.assertEqual((row['status'], row['http_status']), ('ok', 204))
            self.assertEqual(server.posts, [(VM_INSERT, {'Image': 'http://fixture.invalid/image.iso',
                                                          'Inserted': True, 'WriteProtected': True})])
            self.assertTrue(server.vm_inserted)
            inserted = self.call(server, 'virtual-media', VM_MEDIA)['virtual_media']
            self.assertEqual(inserted['flags'] & 17, 17)
            row = self.call(server, 'vm-eject', VM_MEDIA)
            self.assertEqual((row['status'], row['http_status']), ('ok', 204))
            self.assertEqual(server.posts[-1], (VM_EJECT, {}))
            self.assertFalse(server.vm_inserted)
        with self.fixture('vm-no-actions') as server:
            row = self.call(server, 'virtual-media', VM_MEDIA)
            self.assertEqual(row['status'], 'unsupported')
            self.assertEqual(row['virtual_media']['id'], 'cd')
            self.assertEqual(row['virtual_media']['flags'] & 12, 0)
            self.assertEqual(self.call(server, 'vm-insert', VM_MEDIA)['status'], 'unsupported')
            self.assertEqual(server.posts, [])
        # iBMC 3.x shape: null Image/ImageName, empty MediaTypes, only vendor OEM actions.
        with self.fixture('vm-ibmc-shaped') as server:
            row = self.call(server, 'virtual-media', VM_MEDIA)
            self.assertEqual(row['status'], 'unsupported')
            self.assertEqual(row['virtual_media']['id'], 'CD')
            self.assertEqual(row['virtual_media']['image'], '')
            self.assertEqual(row['virtual_media']['image_name'], '')
            self.assertEqual(row['virtual_media']['connected_via'], 'NotConnected')
            self.assertEqual(row['virtual_media']['flags'] & 12, 0)
            self.assertEqual(row['virtual_media']['insert_target'], '')
            self.assertEqual(self.call(server, 'vm-insert', VM_MEDIA)['status'], 'unsupported')
            self.assertEqual(server.posts, [])

    def test_generic_resource_preserves_oem_and_unknown_schema_without_vendor_dispatch(self):
        with self.fixture() as server:
            uri = '/redfish/v1/Managers/arbitrary-controller'
            row = self.call(server, 'resource', uri)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['resource_uri'], uri)
            resource = row['resource']
            self.assertEqual(resource['odata_type'], '#FutureManager.v9_0_0.FutureManager')
            body = json.loads(resource['json'])
            self.assertEqual(json.loads(resource['oem_json']), body['Oem'])
            self.assertEqual(body['FutureProperty'], ['preserve', None, 9007199254740993])
            self.assertEqual(set(body['Oem']), {'AMI', 'Hpe', 'Dell', 'Huawei', 'OpenBmc', 'FutureVendor'})
            self.assertEqual(server.requests, [uri])
            self.assertEqual(server.posts, [])
        with self.fixture() as server:
            row = self.call(server, 'resource', '/redfish/v1/')
            self.assertEqual(row['resource']['oem_json'], '')
        with self.fixture('error') as server:
            row = self.call(server, 'resource', '/redfish/v1/')
            self.assertEqual(row['status'], 'redfish_error')
            self.assertNotIn('resource', row)

    def test_manager_discovery_follows_root_link_and_deduplicates(self):
        with self.fixture() as server:
            row = self.call(server, 'managers')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['collection']['kind'], 5)
            self.assertEqual(row['collection']['members'], [MANAGER])
            self.assertEqual(server.requests, ['/redfish/v1/', MANAGERS])
        with self.fixture('manager-duplicates') as server:
            row = self.call(server, 'managers')
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['collection']['members'], [MANAGER])
        with self.fixture('external-managers') as server:
            self.assertEqual(self.call(server, 'managers')['status'], 'unsupported')

    def test_network_protocol_enabled_ports_and_ntp(self):
        with self.fixture() as server:
            row = self.call(server, 'network-protocol', MANAGER)
            self.assertEqual(row['status'], 'ok')
            protocols = {entry['name']: entry for entry in row['network_protocol']['protocols']}
            self.assertEqual(protocols['NTP'], {'name': 'NTP', 'flags': 7, 'null_flags': 0, 'enabled': True, 'port': 123})
            self.assertEqual(protocols['SSH'], {'name': 'SSH', 'flags': 7, 'null_flags': 0, 'enabled': True, 'port': 22})
            self.assertEqual(protocols['SNMP'], {'name': 'SNMP', 'flags': 3, 'null_flags': 0, 'enabled': False})
            self.assertEqual(protocols['HTTPS'], {'name': 'HTTPS', 'flags': 7, 'null_flags': 0, 'enabled': True, 'port': 443})
            self.assertEqual(protocols['IPMI'], {'name': 'IPMI', 'flags': 7, 'null_flags': 0, 'enabled': True, 'port': 623})
            self.assertEqual(protocols['VirtualMedia'], {'name': 'VirtualMedia', 'flags': 7, 'null_flags': 0, 'enabled': True, 'port': 17988})
            self.assertEqual(protocols['KVMIP'], {'name': 'KVMIP', 'flags': 3, 'null_flags': 0, 'enabled': False})
            info = row['network_protocol']
            self.assertEqual(info['ntp_servers'], ['10.0.0.1', 'ntp.example.com'])
            self.assertEqual(info['ntp_network_supplied'], ['10.0.0.2'])
            self.assertEqual(info['host_name'], 'bmc-host')
            self.assertEqual(info['fqdn'], 'bmc-host.example.com')
            self.assertEqual(server.requests, [MANAGER, NETWORK_PROTOCOL])

    def test_network_protocol_missing_null_and_malformed(self):
        for mode, expected in [('network-null-snmp', 'ok'), ('network-missing-telnet', 'ok')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                row = self.call(server, 'network-protocol', MANAGER)
                self.assertEqual(row['status'], expected)
        with self.fixture('network-bad-port') as server:
            self.assertEqual(self.call(server, 'network-protocol', MANAGER)['status'], 'protocol_error')
        with self.fixture('network-bool-port') as server:
            self.assertEqual(self.call(server, 'network-protocol', MANAGER)['status'], 'protocol_error')
        with self.fixture('network-oversized-ntp') as server:
            self.assertEqual(self.call(server, 'network-protocol', MANAGER)['status'], 'limit_exceeded')
        with self.fixture('network-wrong-type') as server:
            self.assertEqual(self.call(server, 'network-protocol', MANAGER)['status'], 'protocol_error')
        for mode, expected in [('missing-network-protocol', 'unsupported'), ('external-network-protocol', 'unsupported')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'network-protocol', MANAGER)['status'], expected)
                self.assertEqual(server.requests, [MANAGER])

    def test_network_protocol_nullable_port_enabled_and_host_name(self):
        # AST2600 / OpenBMC returns "Port": null for a disabled protocol
        # (DMTF ManagerNetworkProtocol v1.9+ nullable Port); it must parse.
        with self.fixture('network-null-port') as server:
            row = self.call(server, 'network-protocol', MANAGER)
            self.assertEqual(row['status'], 'ok')
            protocols = {entry['name']: entry for entry in row['network_protocol']['protocols']}
            self.assertEqual(protocols['HTTP'],
                             {'name': 'HTTP', 'flags': 7, 'null_flags': 16, 'enabled': False, 'port': None})
            self.assertEqual(protocols['SSH']['port'], 22)
            self.assertEqual(protocols['HTTPS']['port'], 443)
            self.assertEqual(protocols['IPMI']['port'], 623)
            self.assertEqual(row['network_protocol']['host_name'], 'bmc-host')
            self.assertEqual(row['network_protocol']['fqdn'], 'bmc-host.example.com')
        with self.fixture('network-zero-port') as server:
            row = self.call(server, 'network-protocol', MANAGER)
            self.assertEqual(row['status'], 'ok')
            protocols = {entry['name']: entry for entry in row['network_protocol']['protocols']}
            self.assertEqual(protocols['HTTP'],
                             {'name': 'HTTP', 'flags': 7, 'null_flags': 0, 'enabled': False, 'port': 0})
        with self.fixture('network-null-enabled') as server:
            row = self.call(server, 'network-protocol', MANAGER)
            self.assertEqual(row['status'], 'ok')
            protocols = {entry['name']: entry for entry in row['network_protocol']['protocols']}
            self.assertEqual(protocols['SSH'],
                             {'name': 'SSH', 'flags': 7, 'null_flags': 8, 'enabled': None, 'port': 22})
        with self.fixture('network-null-hostname') as server:
            row = self.call(server, 'network-protocol', MANAGER)
            self.assertEqual(row['status'], 'ok')
            self.assertIsNone(row['network_protocol']['host_name'])
            self.assertEqual(row['network_protocol']['fqdn'], 'bmc-host.example.com')
        for mode in ('network-bad-port', 'network-bool-port'):
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'network-protocol', MANAGER)['status'], 'protocol_error')

    def test_ethernet_discovery_pagination_dedup_and_rejections(self):
        with self.fixture() as server:
            row = self.call(server, 'ethernet', MANAGER)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['collection']['kind'], 6)
            self.assertEqual(row['collection']['members'], [ETH0, ETH1])
            self.assertEqual(server.requests, [MANAGER, ETH_COLLECTION, ETH_COLLECTION + '?page=2'])
        with self.fixture('eth-duplicates') as server:
            row = self.call(server, 'ethernet', MANAGER)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['collection']['members'], [ETH0, ETH1])
        with self.fixture('eth-empty') as server:
            self.assertEqual(self.call(server, 'ethernet', MANAGER)['collection']['members'], [])
        with self.fixture('eth-cycle') as server:
            self.assertEqual(self.call(server, 'ethernet', MANAGER)['status'], 'protocol_error')
        for mode, expected in [('missing-ethernet', 'unsupported'), ('external-ethernet', 'unsupported'),
                               ('eth-external-member', 'unsupported')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'ethernet', MANAGER)['status'], expected)
        with self.fixture() as server:
            row = self.call(server, 'ethernet', MANAGER, maximum='1')
            self.assertEqual(row['status'], 'limit_exceeded')
            self.assertEqual(row['collection']['members'], [ETH0])

    def test_ethernet_interface_fields_and_missing_null_split(self):
        with self.fixture() as server:
            row = self.call(server, 'ethernet-interface', ETH0)
            self.assertEqual(row['status'], 'ok')
            info = row['ethernet_interface']
            self.assertEqual(info['mac'], 'aa:bb:cc:dd:ee:ff')
            self.assertEqual(info['state'], 'Enabled')
            self.assertEqual(info['health'], 'OK')
            self.assertEqual(info['dhcp4_enabled'], True)
            self.assertEqual(info['dhcp6_enabled'], False)
            self.assertEqual(info['interface_enabled'], True)
            self.assertEqual(info['link_status'], 'LinkUp')
            self.assertEqual(info['host_name'], 'bmc-host')
            self.assertEqual(info['fqdn'], '')
            self.assertEqual(info['ipv4'][0]['address'], '192.168.1.10')
            self.assertEqual(info['ipv4'][0]['address_origin'], 'DHCP')
            self.assertEqual(info['ipv4'][1]['null_flags'], 2)
            self.assertEqual(info['ipv4'][1]['subnet_mask'], '')
            self.assertEqual(info['ipv6'][0]['prefix_length'], 64)
            self.assertEqual(info['ipv6'][1]['flags'], 1)
            self.assertEqual(info['ipv6'][1]['null_flags'], 1)
            self.assertEqual(server.requests, [ETH0])
        with self.fixture('eth-missing-mac') as server:
            info = self.call(server, 'ethernet-interface', ETH0)['ethernet_interface']
            self.assertEqual(info['flags'] & 1, 0)
            self.assertEqual(info['mac'], '')
        with self.fixture('eth-null-mac') as server:
            info = self.call(server, 'ethernet-interface', ETH0)['ethernet_interface']
            self.assertEqual((info['flags'] & 1, info['null_flags'] & 1), (1, 1))
            self.assertEqual(info['mac'], '')
        with self.fixture('eth-null-status') as server:
            info = self.call(server, 'ethernet-interface', ETH0)['ethernet_interface']
            self.assertEqual((info['flags'] & 6, info['null_flags'] & 6), (6, 6))
            self.assertEqual((info['state'], info['health']), ('', ''))
        with self.fixture('eth-missing-dhcp4') as server:
            info = self.call(server, 'ethernet-interface', ETH0)['ethernet_interface']
            self.assertEqual(info['flags'] & 8, 0)
            self.assertEqual(info['dhcp4_enabled'], 0)

    def test_ethernet_interface_malformed_payloads(self):
        for mode, expected in [('eth-bool-dhcp', 'protocol_error'), ('eth-bad-prefix', 'protocol_error'),
                               ('eth-wrong-type', 'protocol_error'), ('eth-too-many-ipv4', 'limit_exceeded')]:
            with self.subTest(mode=mode), self.fixture(mode) as server:
                self.assertEqual(self.call(server, 'ethernet-interface', ETH0)['status'], expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
