"""Run the Swift C-ABI transport test against the independent RFB fixture."""
import os
import argparse
from pathlib import Path
import subprocess
import sys
import kvm_ws

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--c-build', type=Path, default=root / 'build')
args = parser.parse_args()
c_build = args.c_build.resolve()
server = kvm_ws.RawServer()
server.start()
env = os.environ.copy()
env['DEVELOPER_DIR'] = '/Applications/Xcode.app/Contents/Developer'
env['BC_TEST_KVM_URL'] = 'tcp://127.0.0.1:' + str(server.port)
result = subprocess.run(['swift', 'test', '--package-path', str(root / 'frontends/apple'),
    '--scratch-path', str(root / 'build-apple'), '--disable-sandbox', '-Xcc', '-I', '-Xcc', str(root / 'include'),
    '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'),
    '-Xlinker', '-L', '-Xlinker', str(c_build), '-Xlinker', '-rpath', '-Xlinker', str(c_build), '--filter', 'ConsoleTests.testNativeTransportFrame'], env=env, timeout=120)
server.join(timeout=5)
if server.is_alive():
    server.socket.close()
    raise SystemExit('fixture did not close')
if result.returncode == 0:
    assert bytes([4, 1, 0, 0, 0, 0, 255, 13]) in server.received, 'key press missing'
    assert bytes([4, 0, 0, 0, 0, 0, 255, 13]) in server.received, 'key release missing'
    assert bytes([5, 1, 0, 1, 0, 1]) in server.received, 'pointer press missing'
    assert bytes([5, 0, 0, 1, 0, 1]) in server.received, 'pointer missing'
raise SystemExit(result.returncode)
