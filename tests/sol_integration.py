import os
import socket
import subprocess
import sys
import unittest
import time

CLIENT = sys.argv[1]
AGENT = sys.argv.pop(2)
# Reuse the independent RAKP reference, not product packet encoders.
from ipmi_integration import Bmc, SUITE_17, aes_cbc, digest, build_message, parse_message, packet


class SolBmc(Bmc):
    def __init__(self, mode):
        super().__init__(SUITE_17)
        self.mode = mode
        self.active = mode == 'busy'
        self.owner_queries = self.deactivations = self.tx_packets = 0
        self.privilege_sets = 0
        self.extra = []
        self.after = []
        self.acks = []
        self.first_input = None
        self.inputs = bytearray()
        self.burst_next = 1
        self.burst_acked = 0
        self.burst_inflight = 0
        self.burst_total = 20
        self.burst_suspended = False

    BURST_BYTES = 252

    def burst_packet(self, index):
        data = bytes(((index * 17 + i) % 251) + 1 for i in range(self.BURST_BYTES))
        return self.sol((index % 15) + 1, data=data)

    def serve(self):
        while not self.done:
            try:
                data, address = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                reply = self.handle(data)
                for extra in self.extra:
                    self.socket.sendto(extra, address)
                self.extra.clear()
                if reply:
                    self.socket.sendto(reply, address)
                for extra in self.after:
                    self.socket.sendto(extra, address)
                self.after.clear()
            except Exception as error:
                self.error = error
                return

    def unpack(self, datagram, payload):
        sequence = int.from_bytes(datagram[10:14], 'little')
        assert sequence == self.in_sequence + 1
        self.in_sequence = sequence
        assert datagram[5] & 0xc0 == 0xc0
        length = len(payload)
        pad = (4 - ((12 + length + 2) % 4)) % 4
        assert datagram[16 + length:16 + length + pad + 2] == b'\xff' * pad + bytes([pad, 7])
        assert datagram[-16:] == digest(self.k1, datagram[4:-16], self.algorithm)[:16]
        plain = aes_cbc(self.k2[:16], payload[:16], payload[16:], decrypt=True)
        pad = plain[-1]
        if pad:
            assert plain[-pad - 1:-1] == bytes(range(1, pad + 1))
        return plain[:-pad - 1]

    def wrap(self, plain, kind=0):
        pad = (-(len(plain) + 1)) % 16
        iv = os.urandom(16)
        payload = iv + aes_cbc(self.k2[:16], iv, plain + bytes(range(1, pad + 1)) + bytes([pad]))
        body = bytes([6, kind | 0xc0]) + self.console_id.to_bytes(4, 'little') + self.out_sequence.to_bytes(4, 'little') + len(payload).to_bytes(2, 'little') + payload
        self.out_sequence += 1
        pad = (-(len(body) + 2)) % 4
        body += b'\xff' * pad + bytes([pad, 7])
        return b'\x06\x00\xff\x07' + body + digest(self.k1, body, self.algorithm)[:16]

    def sol(self, seq=0, ack=0, count=0, flags=0, data=b''):
        return self.wrap(bytes([seq, ack, count, flags]) + data, 1)

    def handle(self, datagram):
        if datagram[5] & 0x3f != 1:
            return super().handle(datagram)
        length = int.from_bytes(datagram[14:16], 'little')
        plain = self.unpack(datagram, datagram[16:16 + length])
        seq, ack, count, flags = plain[:4]
        if not seq:
            self.acks.append((ack, count, flags))
            if self.mode == 'backpressure' and (ack, count, flags) == (2, 0, 0):
                return self.sol(2, data=b'b' * 200)
            if self.mode == 'burst':
                if flags & 0x40:
                    self.burst_suspended = True
                    return None
                if self.burst_suspended and count == 0:
                    self.burst_suspended = False
                    return self.burst_packet(self.burst_inflight)
                if count and not self.burst_suspended:
                    self.burst_acked += 1
                    if self.burst_next < self.burst_total:
                        packet = self.burst_packet(self.burst_next)
                        self.burst_inflight = self.burst_next
                        self.burst_next += 1
                        return packet
            return None
        self.tx_packets += 1
        self.inputs.extend(plain[4:])
        if self.mode == 'zero-ack' or (self.mode == 'first-zero-ack' and self.tx_packets == 1):
            return self.sol(ack=seq, count=0)
        if self.mode == 'no-ack':
            return None
        if self.mode == 'bad-ack':
            return self.sol(ack=seq, count=255)
        if self.mode in ('transfer', 'partial-ack'):
            if self.tx_packets == 1:
                assert plain[4:] == b'abcdef'
                self.first_input = plain
                return None
            if self.tx_packets == 2:
                assert plain == self.first_input
                return self.sol(1, seq, 2, 0 if self.mode == 'partial-ack' else 0x40, b'hello')
            assert seq != self.first_input[0] and plain[4:] == b'cdef'
            duplicate = self.sol(1, data=b'hello!')
            self.extra.extend([duplicate, duplicate, self.sol(1, data=b'hello'), self.sol(1, data=b'hello!')])
            return self.sol(ack=seq, count=4)
        return self.sol(ack=seq, count=len(plain) - 4)

    def command(self, datagram, payload):
        _, netfn, _, _, sequence, command, data = parse_message(self.unpack(datagram, payload))
        if netfn == 6 and command == 0x3b:
            assert data == b'\x04'
            self.privilege_sets += 1
            response = b'\x04'
        elif command == 0x4e:
            if self.mode == 'ilom' and data == b'\x0e':
                return self.wrap(build_message(netfn + 1, command, b'', sequence, completion=0xcc))
            response = b'\x03' + bytes(7)
        elif command == 0x4f:
            response = b'\x20' if self.mode == 'unsupported-version' else b'\x10'
        elif netfn == 12 and command == 0x22:
            if self.mode == 'ilom':
                return self.wrap(build_message(netfn + 1, command, b'', sequence, completion=0xc1))
            parameter = data[1]
            response = bytes([0x11]) + {1: b'\x01', 2: b'\x02', 5: b'\x07', 6: b'\x07', 7: b'\x01', 8: self.port.to_bytes(2, 'little')}[parameter]
        elif command == 0x4a:
            # Huawei-flavoured BMCs report a capability byte instead of the
            # highest payload instance; the core must not treat it as an
            # instance count.
            response = bytes([0x10 if self.mode == 'ibmc-bytes' else 15, int(self.active), 0])
        elif command == 0x48:
            assert data == b'\x01\x01\xc4\0\0\0'
            self.active = True
            if self.mode == 'lost-activate':
                return None
            port = self.port + (1 if self.mode == 'port' else 0)
            size = 255 if self.mode == 'burst' else 259
            response = bytes(4) + size.to_bytes(2, 'little') * 2 + port.to_bytes(2, 'little') + b'\xff\xff'
        elif command == 0x4b:
            self.owner_queries += 1
            owner = self.bmc_id if self.active else 0
            if self.mode == 'owner' and self.owner_queries > 1:
                owner ^= 2
            response = owner.to_bytes(4, 'big' if self.mode == 'ibmc-bytes' else 'little') + bytes(8)
            if self.mode == 'backpressure' and self.owner_queries == 1:
                self.extra.extend([self.sol(1, data=b'a' * 200), self.sol(2, data=b'b' * 200)])
            if self.mode == 'cli' and self.owner_queries == 1:
                self.extra.extend([self.sol(1, data=b'\xe4\xb8'), self.sol(2, data=b'\xad\r\n')])
            if self.mode == 'unprotected' and self.owner_queries == 1:
                self.extra.append(packet(6, 1, self.console_id, self.out_sequence, b'\x01\0\0\0x'))
                self.out_sequence += 1
            if self.mode == 'burst' and self.owner_queries == 1:
                self.burst_inflight = 0
                self.extra.append(self.burst_packet(0))
        elif command == 0x49:
            self.deactivations += 1
            self.active = False
            response = b''
            self.after.append(packet(6, 1, self.console_id, self.out_sequence, b'\0\0\0\x10'))
            self.out_sequence += 1
        elif command == 0x3c:
            response = b''
        else:
            raise AssertionError((netfn, command))
        return self.wrap(build_message(netfn + 1, command, response, sequence))


class Sol(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'POSIX PTY restoration')
    def test_terminal(self):
        import array
        import fcntl
        import pty
        import select
        import signal
        import termios
        for action in ('escape', 'signal'):
            with self.subTest(action=action), SolBmc('cli') as bmc:
                master, slave = pty.openpty()
                saved = termios.tcgetattr(slave)
                environment = dict(os.environ, BC_BMC_USERNAME='admin', BC_BMC_PASSWORD='test-password')
                process = subprocess.Popen([AGENT, 'sol', '--host', '127.0.0.1', '--port', str(bmc.port)],
                                           stdin=slave, stdout=slave, stderr=slave, env=environment)
                output = bytearray()
                try:
                    deadline = time.monotonic() + 5
                    while b'SOL connected' not in output and time.monotonic() < deadline:
                        if select.select([master], [], [], .1)[0]:
                            output.extend(os.read(master, 4096))
                    self.assertIn(b'SOL connected', output)
                    if action == 'escape':
                        os.write(master, b'~~x\r~.')
                    else:
                        process.send_signal(signal.SIGTERM)
                    result = process.wait(5)
                    while select.select([master], [], [], .1)[0]:
                        output.extend(os.read(master, 4096))
                    self.assertEqual(result, 0, output.decode(errors='replace'))
                    self.assertEqual(bmc.privilege_sets, 1)
                    if sys.platform == 'darwin':
                        # Darwin sets PENDIN on raw -> canonical; process it without reading/discarding input.
                        fcntl.ioctl(slave, termios.FIONREAD, array.array('i', [0]))
                    self.assertEqual(termios.tcgetattr(slave), saved)
                    self.assertIn(b'\xe4\xb8\xad', output)
                    self.assertEqual(bytes(bmc.inputs), b'~x\r' if action == 'escape' else b'')
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    os.close(slave)
                    os.close(master)

    def test_protocol(self):
        for mode in ('transfer', 'partial-ack', 'first-zero-ack', 'zero-ack', 'backpressure', 'burst', 'busy', 'port', 'lost-activate', 'owner', 'bad-ack', 'no-ack', 'unsupported-version', 'unprotected', 'ibmc-bytes', 'ilom'):
            with self.subTest(mode=mode), SolBmc(mode) as bmc:
                result = subprocess.run([CLIENT, str(bmc.port), mode], capture_output=True, timeout=12)
                self.assertEqual(result.returncode, 0, result.stderr.decode() + f' fixture_error={bmc.error!r}')
                self.assertEqual(bmc.privilege_sets, 1)
                self.assertEqual(bmc.deactivations, 0 if mode in ('busy', 'owner', 'unsupported-version') else 1)
                self.assertTrue(all(ack for ack, _, _ in bmc.acks))
                if mode == 'transfer':
                    self.assertGreaterEqual(bmc.tx_packets, 3)
                    self.assertIn((1, 6, 0), bmc.acks)
                if mode == 'backpressure':
                    self.assertIn((2, 0, 0x40), bmc.acks)
                    self.assertIn((2, 0, 0), bmc.acks)
                if mode == 'burst':
                    self.assertEqual(bmc.burst_acked, bmc.burst_total)


if __name__ == '__main__':
    unittest.main()
