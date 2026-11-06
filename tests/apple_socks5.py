"""Run a selected Apple integration test against a refusing SOCKS5 proxy."""
import os
import json
import base64
import hashlib
import struct
import ssl
import tempfile
from contextlib import ExitStack
import socket
import subprocess
import sys
import threading


def exact(conn, size):
    data = b''
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError('truncated SOCKS5 request')
        data += part
    return data


def ws_send(conn, data):
    length = len(data)
    header = bytes([130, length]) if length < 126 else bytes([130, 126]) + struct.pack('>H', length) if length < 65536 else bytes([130, 127]) + struct.pack('>Q', length)
    conn.sendall(header + data)


def ws_receive(conn):
    first, second = exact(conn, 2)
    assert first == 130 and second & 128
    length = second & 127
    if length == 126:
        length = struct.unpack('>H', exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack('>Q', exact(conn, 8))[0]
    assert length <= 65536
    mask, payload = exact(conn, 4), exact(conn, length)
    return bytes(value ^ mask[index % 4] for index, value in enumerate(payload))


def idrac_console(conn, headers):
    accept = base64.b64encode(hashlib.sha1((headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
    conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: binary\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
    ws_send(conn, bytes([247, 179]))
    assert ws_receive(conn) == bytes([247, 179]) + b'fixture-secondary' + bytes(8)
    ws_send(conn, b'RFB 003.008\n')
    assert ws_receive(conn) == b'RFB 003.008\n'
    ws_send(conn, bytes([1, 1]))
    assert ws_receive(conn) == b'\x01'
    ws_send(conn, bytes(4))
    assert ws_receive(conn) == b'\x01'
    pixel_format = bytes([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0])
    ws_send(conn, struct.pack('>HH', 256, 128) + pixel_format + bytes(4))
    assert ws_receive(conn)
    ws_send(conn, bytes([0, 0, 0, 1]) + struct.pack('>HHHHi', 0, 0, 256, 128, 0) + bytes([51, 34, 17, 0]) * (256 * 128))
    events = b''
    while not events.endswith(bytes([247, 0, 249])):
        events += ws_receive(conn)
        assert len(events) <= 4096
    assert bytes([246, 1, 0, 0, 0, 0, 0, 97]) in events
    assert bytes([246, 0, 0, 0, 0, 0, 0, 97]) in events
    assert bytes([5, 1, 0, 40, 0, 30]) in events
    assert bytes([5, 0, 0, 40, 0, 30]) in events


def main():
    errors, targets = [], []
    stop = threading.Event()
    certificates = tempfile.TemporaryDirectory()
    tls = None
    if os.environ.get('BC_TEST_APPLE_HTTP') == '1':
        cert, key = certificates.name + '/cert.pem', certificates.name + '/key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=bmc.invalid', '-keyout', key, '-out', cert],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        listener.settimeout(0.2)

        def serve():
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with ExitStack() as sockets:
                        sockets.enter_context(conn)
                        conn.settimeout(3)
                        greeting = exact(conn, 2)
                        assert greeting[0] == 5
                        assert 2 in exact(conn, greeting[1])
                        conn.sendall(b'\x05\x02')
                        assert exact(conn, 2) == b'\x01\x0a'
                        assert exact(conn, 10) == b'proxy-user'
                        assert exact(conn, 1) == b'\x0c'
                        assert exact(conn, 12) == b'proxy-secret'
                        conn.sendall(b'\x01\x00')
                        assert exact(conn, 4) == b'\x05\x01\x00\x03'
                        assert exact(conn, exact(conn, 1)[0]) == b'bmc.invalid'
                        targets.append(int.from_bytes(exact(conn, 2), 'big'))
                        if os.environ.get('BC_TEST_APPLE_HTTP') == '1':
                            conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                            conn = sockets.enter_context(tls.wrap_socket(conn, server_side=True))
                            if os.environ.get('BC_TEST_APPLE_TLS_DIAGNOSTIC') == '1':
                                assert conn.recv(1) == b''  # No HTTP request or device credentials.
                                continue
                            request = b''
                            while not request.endswith(b'\r\n\r\n'):
                                request += exact(conn, 1)
                                assert len(request) <= 16384
                            lines = request.decode('ascii').split('\r\n')
                            method, path, _ = lines[0].split(' ')
                            headers = {name.lower(): value for name, value in (line.split(': ', 1) for line in lines[1:] if line)}
                            if int(headers.get('content-length', '0')):
                                exact(conn, int(headers['content-length']))
                            if os.environ.get('BC_TEST_APPLE_HTTP_CANCEL') == '1':
                                if len(targets) == 1:
                                    assert (method, path) == ('POST', '/session')
                                    with open(certificates.name + '/ready', 'w'):
                                        pass
                                    assert conn.recv(1) == b''
                                else:
                                    assert (method, path) == ('DELETE', '/session')
                                    conn.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}')
                                continue
                            idrac = os.environ.get('BC_TEST_APPLE_IDRAC') == '1'
                            session_path = '/sysmgmt/2015/bmc/session' if idrac else '/session'
                            launch_path = '/sysmgmt/2015/server/vconsole?type=eHTML5' if idrac else '/launch'
                            payload, status = b'{}', b'200 OK'
                            if len(targets) == 1:
                                assert (method, path) == ('POST', session_path)
                                if idrac:
                                    assert headers['user'] == '"user"' and headers['password'] == '"secret"'
                                    payload = b'{"authResult":0}'
                                extra = b'XSRF-TOKEN: csrf-token\r\nX-Auth-Token: redfish-token\r\nSet-Cookie: sid=fixture; Path=/; HttpOnly\r\n'
                            else:
                                assert headers.get('cookie') == 'sid=fixture'
                                if idrac and len(targets) == 3:
                                    assert (method, path) == ('GET', '/vnc/vconsole?vck=fixture-ticket')
                                    assert headers.get('upgrade') == 'websocket'
                                    if os.environ.get('BC_TEST_APPLE_IDRAC_FRAME') == '1':
                                        idrac_console(conn, headers)
                                        continue
                                    status = b'403 Forbidden'
                                else:
                                    assert (method, path) == (('GET', launch_path) if len(targets) == 2 else ('DELETE', session_path))
                                    assert headers.get('xsrf-token') == 'csrf-token'
                                if idrac and len(targets) == 2:
                                    payload = json.dumps({'Location': '/restgui/vconsole/index.html?ip=bmc.invalid&kvmport=443&VCSID=fixture-ticket&VCSID2=fixture-secondary'}).encode()
                                extra = b''
                            conn.sendall(b'HTTP/1.1 ' + status + b'\r\nConnection: close\r\nContent-Length: ' + str(len(payload)).encode() + b'\r\n' + extra + b'\r\n' + payload)
                        else:
                            conn.sendall(b'\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00')
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            environment = dict(os.environ, BC_TEST_APPLE_SOCKS_PORT=str(listener.getsockname()[1]))
            environment['BC_TEST_APPLE_HTTP_READY'] = certificates.name + '/ready'
            result = subprocess.run(sys.argv[1:], env=environment, timeout=120)
        finally:
            stop.set()
            worker.join(4)
        assert not worker.is_alive()
        if errors:
            raise errors[0]
        assert result.returncode == 0, result.returncode
        expected = [int(value) for value in os.environ.get('BC_TEST_APPLE_SOCKS_TARGETS', '443,2198').split(',')]
        assert sorted(targets) == sorted(expected), targets
        print('Verified authenticated remote-DNS routing:', targets)
    certificates.cleanup()


if __name__ == '__main__':
    main()
