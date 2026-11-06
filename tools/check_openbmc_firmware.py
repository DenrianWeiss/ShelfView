"""Read a running OpenBMC firmware through the built Agent and public C API."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, default=Path('build/bcontrol-agent'))
    parser.add_argument('--typed-client', type=Path, default=Path('build/bcontrol-redfish-client'))
    parser.add_argument('--endpoint', default='https://127.0.0.1:2443')
    parser.add_argument('--cert-policy', choices=['strict', 'skip-chain', 'skip-all'], default='strict')
    parser.add_argument('--ca', default='')
    parser.add_argument('--timeout-ms', type=int, default=30000)
    args = parser.parse_args()
    if not 1 <= args.timeout_ms <= 2**31 - 1:
        parser.error('timeout-ms must be in 1..2147483647')

    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout_ms / 1000 * 70 + 10)
        if result.returncode:
            raise RuntimeError('verification client exited with code ' + str(result.returncode))
        return json.loads(result.stdout)

    def raw(path):
        command = [str(args.agent.resolve()), 'inspect', '--endpoint', args.endpoint,
                   '--cert-policy', args.cert_policy, '--path', path, '--timeout-ms', str(args.timeout_ms)]
        if args.ca:
            command += ['--ca', args.ca]
        row = run(command)[0]
        if row['status'] != 'ok':
            raise RuntimeError('resource read failed: ' + row['status'])
        return row

    def typed(action, uri=''):
        row = run([str(args.typed_client.resolve()), args.endpoint, args.ca, action, uri,
                   '0', args.cert_policy, str(args.timeout_ms)])
        if row['status'] != 'ok' or row['completion_count'] != 1:
            raise RuntimeError('typed read failed: ' + row['status'])
        return row

    root = raw('/redfish/v1/')
    discovery = typed('discover')
    if not discovery['systems']:
        raise RuntimeError('no ComputerSystem advertised')
    system_uri = discovery['systems'][0]
    system, reset = typed('system', system_uri), typed('capabilities', system_uri)
    report = {
        'redfish_version': discovery['redfish_version'],
        'tls_version': root['tls_version'], 'verification': root['verification'],
        'systems': discovery['systems'], 'observed_system': system_uri,
        'power_state': system['raw_power_state'],
        'reset_target': reset['reset_target'], 'supported_reset_types': reset['supported_reset_types'],
        'power_command_sent': False,
    }
    chassis_link = root['body'].get('Chassis', {}).get('@odata.id')
    if chassis_link:
        members = typed('chassis')['collection']['members']
        report['chassis'] = members
        if members:
            sensors = typed('sensors', members[0])
            sensor_members = sensors['collection']['members']
            report['sensors'] = {'uri': sensors['resource_uri'], 'member_count': len(sensor_members), 'members': sensor_members}
            if sensor_members:
                report['sample_sensor'] = typed('sensor', sensor_members[0])['sensor']
                report['sample_sensor_details'] = typed('sensor-details', sensor_members[0])['sensor_details']
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
