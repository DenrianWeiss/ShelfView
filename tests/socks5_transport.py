import socket
import subprocess
import sys
import threading
import unittest

CLIENT = sys.argv.pop(1)

def exact(conn, length):
    result = b''
    while len(result) < length:
        part = conn.recv(length - len(result))
        if not part:
            raise EOFError('truncated client message')
        result += part
    return result

class SocksTransport(unittest.TestCase):
    def run_proxy(self, address, encoded, failure=None):
        errors = []
        listener = socket.socket()
        try:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
        except BaseException:
            listener.close()
            raise
        listener.settimeout(5)
        def serve():
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(3)
                    self.assertEqual(exact(conn, 3), b'\x05\x01\x02')
                    if failure == 'downgrade':
                        conn.sendall(b'\x05\x00')
                        self.assertEqual(conn.recv(1), b'')
                        return
                    conn.sendall(b'\x05\x02')
                    self.assertEqual(exact(conn, 13), b'\x01\x04user\x06secret')
                    conn.sendall(b'\x01\x01' if failure == 'auth' else b'\x01\x00')
                    if failure == 'auth':
                        self.assertEqual(conn.recv(1), b'')
                        return
                    self.assertEqual(exact(conn, len(encoded)+3), b'\x05\x01\x00'+encoded)
                    reply = b'\x05\x00\x00\x01\x7f\x00\x00\x01\x12\x34'
                    for value in reply:
                        conn.sendall(bytes([value]))
                    self.assertEqual(exact(conn,4),b'ping')
                    conn.sendall(b'pong')
            except BaseException as exc:
                errors.append(exc)
            finally:
                listener.close()
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            result = subprocess.run([CLIENT,str(listener.getsockname()[1]),address,'16' if failure else '0'],
                                    capture_output=True,text=True,timeout=6)
        finally:
            worker.join(6)
        self.assertFalse(worker.is_alive())
        if errors:
            raise errors[0]
        self.assertEqual(result.returncode,0,result.stderr)

    def test_remote_dns(self):
        self.run_proxy('tcp://bmc.invalid:443', b'\x03\x0bbmc.invalid\x01\xbb')

    def test_ipv4(self):
        self.run_proxy('tcp://192.0.2.1:623', b'\x01\xc0\x00\x02\x01\x02\x6f')

    def test_ipv6(self):
        self.run_proxy('tcp://[2001:db8::1]:443', b'\x04'+socket.inet_pton(socket.AF_INET6,'2001:db8::1')+b'\x01\xbb')

    def test_auth_rejected(self):
        self.run_proxy('tcp://bmc.invalid:443',b'', 'auth')

    def test_no_auth_downgrade(self):
        self.run_proxy('tcp://bmc.invalid:443',b'', 'downgrade')

if __name__ == '__main__':
    unittest.main()
