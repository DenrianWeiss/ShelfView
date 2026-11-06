"""Launch a supplied, hash-verified OpenBMC image in local QEMU."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--sha256', required=True, help='Expected digest from your trusted artifact record')
    parser.add_argument('--qemu', default='qemu-system-arm')
    parser.add_argument('--machine', choices=['romulus-bmc', 'ast2600-evb'], default='romulus-bmc')
    parser.add_argument('--https-port', type=int, default=2443)
    parser.add_argument('--ipmi-port', type=int, default=2623)
    parser.add_argument('--qmp-socket', type=Path, help='Optional local Unix socket for QEMU diagnostics')
    args = parser.parse_args()
    if any(not 1 <= p <= 65535 for p in (args.https_port, args.ipmi_port)):
        parser.error('ports must be in 1..65535')
    expected = args.sha256.lower()
    if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
        parser.error('sha256 must contain exactly 64 hexadecimal characters')
    binary = shutil.which(args.qemu)
    if not binary:
        parser.error('qemu-system-arm not found; install QEMU separately as a validation tool')
    if not args.image.is_file():
        parser.error('image file not found')
    if args.qmp_socket is not None and any(c in str(args.qmp_socket) for c in ',\r\n\x00'):
        parser.error('qmp-socket path must not contain commas, newlines or NUL')
    if args.qmp_socket is not None and args.qmp_socket.is_symlink():
        parser.error('qmp-socket requires an unused path')
    qmp_socket = args.qmp_socket.resolve() if args.qmp_socket is not None else None
    if qmp_socket is not None:
        if any(c in str(qmp_socket) for c in ',\r\n\x00'):
            parser.error('qmp-socket path must not contain commas, newlines or NUL')
        if not qmp_socket.parent.is_dir() or qmp_socket.exists():
            parser.error('qmp-socket requires an existing parent directory and an unused path')
    with tempfile.TemporaryDirectory(prefix='bcontrol-openbmc-') as work:
        image = Path(work) / 'image.static.mtd'
        shutil.copyfile(args.image, image)
        with image.open('rb') as stream:
            observed = hashlib.file_digest(stream, 'sha256').hexdigest()
        if observed != expected:
            parser.error('image SHA-256 mismatch')
        memory = '256M' if args.machine == 'romulus-bmc' else '1G'
        command = [binary, '-m', memory, '-M', args.machine, '-nographic',
                   '-drive', 'file=' + str(image) + ',format=raw,if=mtd',
                   '-net', 'nic', '-net', 'user,hostfwd=tcp:127.0.0.1:' + str(args.https_port) +
                   '-:443,hostfwd=udp:127.0.0.1:' + str(args.ipmi_port) + '-:623,hostname=qemu']
        if qmp_socket is not None:
            command += ['-qmp', 'unix:' + str(qmp_socket) + ',server=on,wait=off']
        try:
            return subprocess.call(command)
        except KeyboardInterrupt:
            return 130


if __name__ == '__main__':
    raise SystemExit(main())
