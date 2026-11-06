import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

AGENT = str(Path(sys.argv.pop(1)).resolve())


def receive(connection, size):
    data = b''
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise EOFError
        data += part
    return data


def packet(connection):
    head = receive(connection, 32)
    return head + receive(connection, struct.unpack_from('<I', head, 12)[0])


def request(opcode, amount, block=0):
    data = bytearray(61)
    data[:8] = b'IUSB    '
    data[8], data[10], data[17], data[18] = 1, 32, 5, 1
    struct.pack_into('<I', data, 12, 29)
    data[11] = (-sum(data[:32])) & 255
    struct.pack_into('<I', data, 32, amount)
    data[36], data[40], data[41] = 7, 1, opcode
    struct.pack_into('>I', data, 43, block)
    struct.pack_into('>H', data, 48, 1)
    return data


class Media(unittest.TestCase):
    def run_case(self, mode, tunnel=False):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        errors = []

        def serve():
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(3)
                    if tunnel:
                        expected = ('CONNECT 127.0.0.1:' + str(listener.getsockname()[1]) +
                                    ' HTTP/1.1\r\n cookie fixture-cookie\r\n\r\n'
                                    'JVIEWER CDMEDIA cookie fixture-cookie\r\n\r\n').encode()
                        self.assertEqual(receive(conn, len(expected)), expected)
                        for byte in b'HTTP/1.0 200 OK  \r\n\r\n\0':
                            conn.sendall(bytes([byte]))
                    auth = packet(conn)
                    self.assertEqual((len(auth), auth[41], auth[63:76]), (160, 0xf2, b'fixture-token'))
                    self.assertEqual(sum(auth[:32]) & 255, 0)
                    status = bytearray(87)
                    status[:8] = b'IUSB    '
                    status[12], status[41], status[62] = 55, 0xf1, 1
                    for byte in status:
                        conn.sendall(bytes([byte]))
                    if mode == 'eof':
                        return
                    conn.sendall(request(0x00, 0))
                    attention = packet(conn)
                    self.assertEqual(attention[53:57], bytes([1, 6, 0x28, 0]))
                    sense_request = request(0x03, 18)
                    sense_request[45] = 18
                    conn.sendall(sense_request)
                    sense = packet(conn)
                    self.assertEqual((sense[63], sense[73:75]), (6, bytes([0x28, 0])))
                    if mode == 'write':
                        conn.sendall(request(0x2a, 2048, 1))
                        denied = packet(conn)
                        self.assertEqual(denied[53:57], bytes([1, 7, 0x27, 0]))
                        conn.sendall(sense_request)
                        sense = packet(conn)
                        self.assertEqual((sense[63], sense[73:75]), (7, bytes([0x27, 0])))
                    else:
                        poll = bytearray(62)
                        poll[:8] = b'IUSB    '
                        poll[12], poll[41] = 30, 0xf3
                        conn.sendall(poll)
                        reply = packet(conn)
                        self.assertEqual((len(reply), reply[41], sum(reply) & 255), (61, 0xf3, 0))
                        self.assertEqual(reply[53:57], bytes([1, 5, 0x20, 0]))
                        conn.sendall(request(0x25, 8))
                        capacity = packet(conn)
                        self.assertEqual(capacity[61:], struct.pack('>II', 1, 2048))
                        self.assertEqual(capacity[36], 7)
                        conn.sendall(request(0x28, 2048, 1))
                        data = packet(conn)
                        self.assertEqual(data[61:], b'Z' * 2048)
                        self.assertEqual(sum(data[:32]) & 255, 0)
                    if tunnel:
                        disconnect = packet(conn)
                        self.assertEqual((len(disconnect), disconnect[41]), (62, 0xf7))
                    self.assertEqual(conn.recv(1), b'')
            except Exception as error:
                errors.append(error)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory(prefix='bcontrol-cd-') as directory:
            source = Path(directory) / 'image.iso'
            original = bytes(2048) + b'Z' * 2048
            source.write_bytes(original)
            env = os.environ.copy()
            env['BC_KVM_TOKEN'] = 'fixture-token'
            env['BC_WEB_COOKIE'] = 'fixture-cookie'
            result = subprocess.run([AGENT, 'megarac-media', '--url', 'tcp://127.0.0.1:' + str(listener.getsockname()[1]),
                                     '--file', str(source), '--seconds', '1'] + (['--single-port-host', '127.0.0.1'] if tunnel else []), env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(source.read_bytes(), original)
        thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [], errors)
        row = json.loads(result.stdout)
        self.assertTrue(row['authenticated'])
        self.assertTrue(row['transport_closed'])
        self.assertEqual(row['status'], {'read': 'ok', 'write': 'ok', 'eof': 'io_error'}[mode])
        if mode == 'read':
            self.assertEqual((row['requests'], row['bytes']), (5, 2074))
        if mode == 'write':
            self.assertEqual((row['requests'], row['bytes']), (4, 36))
        self.assertEqual(result.returncode, 1 if mode == 'eof' else 0, result.stderr)

    def test_fragmented_auth_capacity_and_source_read(self):
        self.run_case('read')

    def test_single_port_read_and_disconnect(self):
        self.run_case('read', tunnel=True)

    def test_write_rejected_and_source_preserved(self):
        self.run_case('write')

    def test_disconnect_is_not_reported_as_timeout(self):
        self.run_case('eof')


if __name__ == '__main__':
    unittest.main(verbosity=2)
