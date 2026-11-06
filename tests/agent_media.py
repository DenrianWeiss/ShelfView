import base64
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import unittest

import agent_api
NODE = sys.argv.pop(1)


class WebSocket:
    def __init__(self, port, origin=agent_api.ORIGIN):
        self.socket = socket.create_connection(('127.0.0.1', port), timeout=8)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        self.socket.sendall(('GET /v1/media/ws HTTP/1.1\r\nHost: 127.0.0.1:' + str(port) + '\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ' + key + '\r\nSec-WebSocket-Version: 13\r\nOrigin: ' + origin + '\r\n\r\n').encode())
        self.buffer = bytearray()
        while b'\r\n\r\n' not in self.buffer:
            chunk = self.socket.recv(4096)
            if not chunk:
                self.socket.close()
                raise ConnectionError('WebSocket handshake rejected')
            self.buffer.extend(chunk)
        headers, remaining = self.buffer.split(b'\r\n\r\n', 1)
        self.buffer = bytearray(remaining)
        if b' 101 ' not in headers.split(b'\r\n', 1)[0]:
            self.socket.close()
            raise ConnectionError('WebSocket handshake rejected')

    def read(self, count):
        while len(self.buffer) < count:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise EOFError('WebSocket closed')
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def receive(self):
        first, length = self.read(2)
        if length & 128:
            raise AssertionError('server frame must not be masked')
        if length == 126:
            length = struct.unpack('!H', self.read(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', self.read(8))[0]
        return first & 15, self.read(length)

    def send(self, opcode, data, final=True):
        data = data.encode() if isinstance(data, str) else data
        header = bytes([(128 if final else 0) | opcode])
        if len(data) < 126:
            header += bytes([128 | len(data)])
        elif len(data) <= 65535:
            header += bytes([128 | 126]) + struct.pack('!H', len(data))
        else:
            header += bytes([128 | 127]) + struct.pack('!Q', len(data))
        mask = secrets.token_bytes(4)
        self.socket.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def close(self):
        self.socket.close()


class Media(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        agent_api.AgentAPI.setUpClass()
        cls.helper = agent_api.AgentAPI()

    @classmethod
    def tearDownClass(cls):
        agent_api.AgentAPI.tearDownClass()

    def pair(self, secret):
        status, pair, _ = self.helper.call('POST', '/v1/pair', {'secret': secret, 'name': 'media-test'})
        self.assertEqual(status, 201)
        return pair

    def test_browser_blob_worker_to_agent_read_and_revocation(self):
        for tls in (False, True):
            with self.subTest(tls=tls), self.helper.running(tls=tls) as (secret, _):
                env = os.environ.copy()
                env['BC_TEST_PAIR_SECRET'] = secret
                env['NODE_EXTRA_CA_CERTS'] = str(self.helper.root / 'cert')
                script = Path(__file__).resolve().parents[1] / 'frontends/web/tests/agent-media-client.mjs'
                origin = ('https' if tls else 'http') + '://127.0.0.1:' + str(self.helper.port)
                result = subprocess.run([NODE, str(script), origin], env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = json.loads(result.stdout)
                self.assertTrue(summary['real_blob_read'] and summary['worker'] and summary['revoked_channel_closed'])

    def test_browser_blob_mount_range_read_and_local_cleanup(self):
        with self.helper.running(tls=True, device_mode='session', media=True) as (secret, _):
            env = os.environ.copy()
            env.update(BC_TEST_PAIR_SECRET=secret, BC_TEST_MEDIA_MOUNT='1', NODE_EXTRA_CA_CERTS=str(self.helper.root / 'cert'))
            script = Path(__file__).resolve().parents[1] / 'frontends/web/tests/agent-media-client.mjs'
            result = subprocess.run([NODE, str(script), 'https://127.0.0.1:' + str(self.helper.port)], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['device_mounted_from_blob'])
            self.assertEqual(self.helper.device.vm_fetched, bytes(i % 251 for i in range(100, 200)))
            self.assertFalse(self.helper.device.vm_inserted)
            self.assertEqual(self.helper.device.vm_ejects, 1)

    def test_fragmented_auth_and_data_preserve_64_bit_offsets(self):
        with self.helper.running() as (secret, _):
            pair = self.pair(secret)
            status, ticket, _ = self.helper.call('POST', '/v1/media/tickets', {'name': 'synthetic-large-source', 'size': str(2**64 - 1)}, token=pair['token'])
            self.assertEqual(status, 201)
            ws = WebSocket(self.helper.port)
            try:
                auth = json.dumps({'ticket': ticket['ticket']})
                ws.send(1, auth[:9], final=False)
                ws.send(9, b'ping')
                ws.send(0, auth[9:])
                self.assertEqual(ws.receive(), (10, b'ping'))
                opcode, ready = ws.receive()
                self.assertEqual(opcode, 1)
                self.assertEqual(json.loads(ready)['source_id'], ticket['source_id'])
                offset = 2**53 + 1
                def read():
                    connection = http.client.HTTPConnection('127.0.0.1', self.helper.port, timeout=8)
                    try:
                        connection.request('POST', '/v1/media/sources/' + ticket['source_id'] + '/read', json.dumps({'offset': str(offset), 'length': 4}), {'Authorization': 'Bearer ' + pair['token'], 'Content-Type': 'application/json'})
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()
                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    reading = pool.submit(read)
                    opcode, request = ws.receive()
                    self.assertEqual(opcode, 2)
                    header = struct.unpack('!4sHHIIQQII', request[:40])
                    self.assertEqual(header[6], offset)
                    self.assertEqual(struct.unpack('!I', request[40:])[0], 4)
                    frame = struct.pack('!4sHHIIQQII', b'BCTL', 1, 2, ticket['channel'], 0, header[5], offset, 4, 0) + b'abcd'
                    ws.send(2, frame[:13], final=False)
                    ws.send(0, frame[13:])
                    self.assertEqual(reading.result(timeout=5), (200, b'abcd'))
                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    reading = pool.submit(read)
                    opcode, request = ws.receive()
                    self.assertEqual(opcode, 2)
                    status, _, _ = self.helper.call('POST', '/v1/media/sources/' + ticket['source_id'] + '/read', {'offset': str(offset), 'length': 4}, token=pair['token'])
                    self.assertEqual(status, 409)
                    header = struct.unpack('!4sHHIIQQII', request[:40])
                    wrong = struct.pack('!4sHHIIQQII', b'BCTL', 1, 2, ticket['channel'], 0, header[5], offset + 1, 4, 0) + b'bad!'
                    ws.send(2, wrong)
                    self.assertEqual(ws.receive()[0], 8)
                    self.assertEqual(reading.result(timeout=5)[0], 410)
                replay = WebSocket(self.helper.port)
                try:
                    replay.send(1, auth)
                    opcode, _ = replay.receive()
                    self.assertEqual(opcode, 8)
                finally:
                    replay.close()
            finally:
                ws.close()

    def test_frame_limits_mask_and_origin(self):
        with self.helper.running():
            with self.assertRaises(ConnectionError):
                WebSocket(self.helper.port, origin='https://evil.example')
            for malformed, code in [
                (b'\x82\x01x', 1002),
                (b'\x82\xff' + struct.pack('!Q', 1048617) + b'abcd', 1009),
                (b'\xc1\x80abcd', 1002),
                (b'\x09\x80abcd', 1002),
                (b'\x81\x81abcd' + bytes([0xff ^ ord('a')]), 1007),
            ]:
                ws = WebSocket(self.helper.port)
                try:
                    ws.socket.sendall(malformed)
                    opcode, body = ws.receive()
                    self.assertEqual(opcode, 8)
                    self.assertEqual(struct.unpack('!H', body[:2])[0], code)
                finally:
                    ws.close()

    def test_unauthenticated_socket_deadline(self):
        with self.helper.running():
            ws = WebSocket(self.helper.port)
            try:
                opcode, body = ws.receive()
                self.assertEqual(opcode, 8)
                self.assertEqual(struct.unpack('!H', body[:2])[0], 1008)
            finally:
                ws.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
