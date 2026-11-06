import socket
import subprocess
import sys
import threading
import unittest
def exact(conn, length):
    result=b''
    while len(result)<length:
        part=conn.recv(length-len(result))
        if not part: raise EOFError()
        result+=part
    return result

CLIENT=sys.argv.pop(1) if len(sys.argv)>1 else None

class UDPProxy(unittest.TestCase):
    def check_proxy(self, mode='normal', host='192.0.2.1', auth=False, relay_ipv6=False):
        errors=[]
        with socket.socket() as tcp, socket.socket(socket.AF_INET6 if relay_ipv6 else socket.AF_INET,socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1',0)); tcp.listen(1); tcp.settimeout(5)
            udp.bind(('::1' if relay_ipv6 else '127.0.0.1',0)); udp.settimeout(3)
            def serve():
                try:
                    with tcp.accept()[0] as c:
                        c.settimeout(3)
                        method = b'\x02' if auth else b'\x00'
                        self.assertEqual(exact(c,3),b'\x05\x01'+method)
                        c.sendall(b'\x05'+method)
                        if auth:
                            self.assertEqual(exact(c,13),b'\x01\x04user\x06secret')
                            c.sendall(b'\x01\x00')
                        self.assertEqual(exact(c,10),b'\x05\x03\x00\x01'+bytes(6))
                        relay = b'\x04'+socket.inet_pton(socket.AF_INET6,'::1') if relay_ipv6 else b'\x01\x7f\x00\x00\x01'
                        c.sendall(b'\x05\x00\x00'+relay+udp.getsockname()[1].to_bytes(2,'big'))
                        packet,peer=udp.recvfrom(65536)
                        if host=='bmc.invalid': address=b'\x03\x0bbmc.invalid'
                        elif ':' in host: address=b'\x04'+socket.inet_pton(socket.AF_INET6,host)
                        else: address=b'\x01'+socket.inet_pton(socket.AF_INET,host)
                        address+=b'\x02\x6f'
                        self.assertEqual(packet,b'\x00\x00\x00'+address+b'ping')
                        if mode=='closed':
                            return
                        reply=b'\x00\x00'+(b'\x01' if mode=='fragment' else b'\x00')+address+b'pong'
                        if mode=='wrong_source':
                            reply=b'\x00\x00\x00\x01\xc0\x00\x02\x02\x02\x6f'+b'pong'
                        udp.sendto(reply,peer)
                        self.assertEqual(c.recv(1),b'')
                except BaseException as exc:
                    errors.append(exc)
            worker=threading.Thread(target=serve); worker.start()
            expected={'normal':0,'closed':9,'fragment':4,'wrong_source':13}[mode]
            try:
                result=subprocess.run([CLIENT,str(tcp.getsockname()[1]),host,str(expected)]+(['auth'] if auth else []),capture_output=True,text=True,timeout=15)
            finally:
                worker.join(5)
            self.assertFalse(worker.is_alive())
            if errors: raise errors[0]
            self.assertEqual(result.returncode,0,result.stderr)
    def test_authenticated(self): self.check_proxy(auth=True)
    def test_ipv6_target(self): self.check_proxy(host='2001:db8::1')
    @unittest.skipUnless(socket.has_ipv6, 'IPv6 sockets unavailable')
    def test_ipv6_relay(self): self.check_proxy(host='bmc.invalid', auth=True, relay_ipv6=True)
    def test_datagrams(self): self.check_proxy()
    def test_remote_dns(self): self.check_proxy(host='bmc.invalid')
    def test_closed_control(self): self.check_proxy('closed')
    def test_fragment(self): self.check_proxy('fragment')
    def test_wrong_source(self): self.check_proxy('wrong_source')

if __name__=='__main__': unittest.main()
