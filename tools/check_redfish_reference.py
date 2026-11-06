"""Check bControl GET interoperability against DMTF's external mockup server."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-repo', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--typed-client', type=Path, help='Optional built public-C-API test client')
    args = parser.parse_args()
    repo, agent = args.server_repo.resolve(), args.agent.resolve()
    if not (repo / 'redfishMockupServer.py').is_file() or not agent.is_file():
        parser.error('server repository or compiled agent not found')
    with tempfile.TemporaryDirectory(prefix='bcontrol-reference-') as work:
        root = Path(work)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        with (root / 'server.log').open('w') as log:
            server = subprocess.Popen([sys.executable, str(repo / 'redfishMockupServer.py'), '-H', '127.0.0.1', '-p', str(port), '-D', str(repo / 'public-rackmount1'), '-S', '-s', '--cert', str(root / 'cert.pem'), '--key', str(root / 'key.pem')], cwd=repo, stdout=log, stderr=log)
            try:
                ready = False
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError('reference server exited; check its Python dependencies')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            ready = True
                            break
                    except OSError:
                        time.sleep(.05)
                if not ready:
                    raise RuntimeError('reference server did not become ready')

                def get(path):
                    env = os.environ.copy()
                    env.pop('BC_BMC_USERNAME', None)
                    env.pop('BC_BMC_PASSWORD', None)
                    result = subprocess.run([str(agent), 'inspect', '--endpoint', 'https://localhost:' + str(port), '--ca', str(root / 'cert.pem'), '--path', path], env=env, check=True, capture_output=True, text=True, timeout=10)
                    row = json.loads(result.stdout)[0]
                    if row['verification'] != 'verified' or row['http_status'] != 200:
                        raise RuntimeError('reference HTTPS request failed')
                    return row['body']

                service = get('/redfish/v1/')
                systems = get(service['Systems']['@odata.id'])
                system = get(systems['Members'][0]['@odata.id'])
                collection = get(service['Chassis']['@odata.id'])
                chassis = get(collection['Members'][0]['@odata.id'])
                sensors = get(chassis['Sensors']['@odata.id'])
                sensor = get(sensors['Members'][0]['@odata.id'])
                summary = dict(redfish_version=service['RedfishVersion'], system_id=system['Id'], power_state=system.get('PowerState'), sensor_id=sensor['Id'], reading=sensor.get('Reading'), units=sensor.get('ReadingUnits'), verified_https_gets=7)
                if args.typed_client:
                    origin = 'https://localhost:' + str(port)
                    def typed(action, uri=''):
                        process = subprocess.run([str(args.typed_client.resolve()), origin, str(root / 'cert.pem'), action, uri], check=True, capture_output=True, text=True, timeout=10)
                        row = json.loads(process.stdout)
                        if row['status'] != 'ok':
                            raise RuntimeError('typed reference operation failed')
                        return row
                    discovery = typed('discover')
                    if not discovery['systems']:
                        raise RuntimeError('reference fixture unexpectedly has no systems')
                    state = typed('system', discovery['systems'][0])
                    chassis_members = typed('chassis')['collection']['members']
                    sensor_members = typed('sensors', chassis_members[0])['collection']['members']
                    if sensor_members != [m['@odata.id'] for m in sensors['Members']]:
                        raise RuntimeError('typed sensor discovery disagrees with reference payload')
                    reading = typed('sensor', sensor_members[0])['sensor']
                    if reading['reading'] != sensor.get('Reading') or reading['units'] != sensor.get('ReadingUnits'):
                        raise RuntimeError('typed sensor reading disagrees with reference payload')
                    summary.update(typed_discovery=True, typed_system_state=state['raw_power_state'], typed_chassis_count=len(chassis_members), typed_sensor_count=len(sensor_members), typed_sensor=reading['reading'], typed_sensor_units=reading['units'])
                print(json.dumps(summary, indent=2))
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
