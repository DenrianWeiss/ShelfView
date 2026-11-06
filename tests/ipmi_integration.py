import contextlib
import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import unittest

AGENT = str(__import__('pathlib').Path(sys.argv.pop(1)).resolve())
USERNAME = 'admin'
PASSWORD = 'test-password'
SUITE_17 = bytes([0xc0, 0x11, 0x03, 0x04, 0x01])
SUITE_3 = bytes([0xc0, 0x03, 0x01, 0x01, 0x01])
DEVICE_ID = bytes([0x20, 0x01, 0x01, 0x15, 0x02, 0x3f, 0x57, 0x01, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00])


def checksum(data):
    return (256 - sum(data)) & 0xff


def digest(key, data, algorithm='sha256'):
    return hmac.new(key, data, getattr(hashlib, algorithm)).digest()


def aes_cbc(key, iv, data, decrypt=False):
    command = ['openssl', 'enc', '-aes-128-cbc', '-K', key.hex(), '-iv', iv.hex(), '-nopad']
    if decrypt:
        command.append('-d')
    return subprocess.run(command, input=data, capture_output=True, check=True).stdout


def build_message(netfn, command, data, sequence=0, completion=0):
    first = bytes([0x20, netfn << 2])
    second = bytes([0x81, sequence << 2, command, completion]) + data
    return first + bytes([checksum(first)]) + second + bytes([checksum(second)])


def parse_message(message):
    assert len(message) >= 7 and message[2] == checksum(message[0:2])
    assert checksum(message[3:]) == 0
    return (message[0], message[1] >> 2, message[1] & 3, message[3], message[4] >> 2,
            message[5], message[6:-1])


def packet(auth, payload_type, session_id, sequence, payload):
    return bytes([0x06, 0x00, 0xff, 0x07, auth, payload_type]) + session_id.to_bytes(4, 'little') + \
        sequence.to_bytes(4, 'little') + len(payload).to_bytes(2, 'little') + payload


def sel_record(record_id, record_type, payload):
    record = bytearray(16)
    record[0:2] = record_id.to_bytes(2, 'little')
    record[2] = record_type
    record[3:3 + len(payload)] = payload
    return bytes(record)


def sel_event_payload(timestamp, body):
    return timestamp.to_bytes(3, 'little') + body


def fru_checksum(data):
    return (-sum(data)) & 255


def fru_area(body):
    area = bytearray([1, 0]) + bytearray(body)
    while (len(area) + 1) % 8:
        area.append(0)
    area[1] = (len(area) + 1) // 8
    area.append(fru_checksum(area))
    return bytes(area)


def fru_tl(data, encoding=3):
    return bytes([(encoding << 6) | len(data)]) + data


def fru_record(kind, data, end):
    header = bytearray([kind, 2 | (128 if end else 0), len(data), fru_checksum(data)])
    header.append(fru_checksum(header))
    return bytes(header) + data


def fru_image(chassis=None, board=None, product=None, multi=b'', internal=b''):
    parts = []
    offsets = {}
    position = 8
    for name, area in (('internal', internal), ('chassis', chassis), ('board', board),
                       ('product', product), ('multi', multi)):
        if area:
            offsets[name] = position // 8
            parts.append(area)
            position += len(area)
    header = bytearray([1, offsets.get('internal', 0), offsets.get('chassis', 0),
                        offsets.get('board', 0), offsets.get('product', 0), offsets.get('multi', 0), 0])
    header.append(fru_checksum(header))
    return bytes(header) + b''.join(parts)


def standard_fru_image():
    chassis = fru_area(bytes([0x17]) + fru_tl(b'CHAS-CASE') + fru_tl(b'CHASSN1') + b'\xc1')
    board = fru_area(bytes([0, 0xa0, 0xb0, 0x60]) + fru_tl(b'AcmeBoard') + fru_tl(b'BoardOne') +
                     fru_tl(b'BSN-77') + fru_tl(b'BP-1') + fru_tl(b'\x02', encoding=0) + b'\xc1')
    product = fru_area(bytes([0]) + fru_tl(b'Acme') + fru_tl(b'Server') + fru_tl(b'Model') +
                       fru_tl(b'1.0') + fru_tl(b'S123') + fru_tl(b'A456') + b'\xc1')
    multi = fru_record(0xc0, b'\x01\x02\x03', True)
    return fru_image(chassis=chassis, board=board, product=product, multi=multi)


class Bmc:
    def __init__(self, records, password=PASSWORD, legacy=False, cipher_query=True, open_session_ignored=False, auth_unknown=False):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(0.2)
        self.records = records
        self.legacy = legacy
        self.auth_unknown = auth_unknown
        self.cipher_query = cipher_query
        self.open_session_ignored = open_session_ignored
        self.suites = []
        remaining = records
        while len(remaining) >= 5 and remaining[0] == 0xc0:
            self.suites.append((remaining[2] & 0x3f, remaining[3] & 0x3f, remaining[4] & 0x3f))
            remaining = remaining[5:]
        self.key = password.encode().ljust(20, b'\0')
        self.username = USERNAME.encode()
        self.out_sequence = 1
        self.in_sequence = 0
        self.power_action = None
        self.boot_flags = bytes(5)
        self.boot_progress = 0
        self.boot_writes = []
        self.boot_mismatch = False
        self.sel_entries = []
        self.sel_reservation = 0
        self.sel_reservations = 0
        self.sel_info_completion = 0
        self.sel_bad_reservations = 0
        self.sel_record_failures = {}
        self.sel_short_records = {}
        self.fru_devices = {}
        self.fru_word_access = set()
        self.fru_info_completion = 0
        self.fru_read_limit = {}
        self.fru_read_failures = {}
        self.fru_reads = []
        self.chassis_status_bytes = bytes([0x01, 0x00, 0x00, 0x00])
        self.chassis_caps = None
        self.chassis_caps_completion = 0
        self.restart_cause = None
        self.restart_cause_completion = 0
        self.channel_media = {}
        self.lan_params = {}
        self.lan_completion = None
        self.lan_drop_channels = set()
        self.lan_requests = []
        self.done = False
        self.error = None
        self.thread = threading.Thread(target=self.serve, daemon=True)

    @property
    def port(self):
        return self.socket.getsockname()[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.done = True
        self.thread.join(5)
        self.socket.close()
        if self.error and exc[0] is None:
            raise self.error

    def serve(self):
        while not self.done:
            try:
                datagram, address = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                reply = self.handle(datagram)
            except Exception as error:  # noqa: BLE001 - surfaced by the test
                self.error = error
                return
            if reply:
                self.socket.sendto(reply, address)

    def handle(self, datagram):
        assert datagram[0:4] == b'\x06\x00\xff\x07', datagram.hex()
        if datagram[4] == 0x00:
            length = datagram[13]
            _, netfn, _, _, sequence, command, data = parse_message(datagram[14:14 + length])
            if netfn != 0x06 or command != 0x38:
                return None
            if self.auth_unknown and data[0] & 0x80:
                return None
            assert self.auth_unknown or data[0] & 0x80, 'IPMI 2.0 capability data was not requested'
            channel = data[0] & 0x0f
            if self.auth_unknown:
                capabilities = bytes([channel, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00])
            elif self.legacy:
                capabilities = bytes([channel, 0x04, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00])
            else:
                capabilities = bytes([channel, 0x84, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00])
            message = build_message(0x07, command, capabilities, sequence)
            return bytes([0x06, 0x00, 0xff, 0x07, 0x00]) + bytes(8) + bytes([len(message)]) + message
        if self.legacy:
            return None
        auth, payload_type = datagram[4], datagram[5] & 0x3f
        session_id = int.from_bytes(datagram[6:10], 'little')
        assert auth == 0x06
        length = int.from_bytes(datagram[14:16], 'little')
        payload = datagram[16:16 + length]
        if payload_type == 0x00 and session_id == 0:
            return self.sessionless(payload)
        if payload_type == 0x10:
            return None if self.open_session_ignored else self.open_session(payload)
        if payload_type == 0x12:
            return self.rakp1(payload)
        if payload_type == 0x14:
            return self.rakp3(payload)
        if payload_type == 0x00 and session_id == self.bmc_id:
            return self.command(datagram, payload)
        raise AssertionError(f'unexpected payload {payload_type:#x}')

    def sessionless(self, payload):
        _, netfn, _, _, sequence, command, data = parse_message(payload)
        assert netfn == 0x06 and command == 0x54 and sequence < 64
        if not self.cipher_query:
            return None
        channel = data[0]
        index = data[2] & 0x3f
        records = self.records if index == 0 else b''
        message = build_message(0x07, command, bytes([channel]) + records, sequence)
        return packet(0x06, 0x00, 0, 0, message)

    def open_session(self, payload):
        tag, privilege = payload[0], payload[1]
        console_id = int.from_bytes(payload[4:8], 'little')
        algorithms = (payload[12] & 0x3f, payload[20] & 0x3f, payload[28] & 0x3f)
        response = bytearray(36)
        response[0] = tag
        response[2] = privilege
        response[4:8] = console_id.to_bytes(4, 'little')
        if algorithms not in self.suites:
            response[1] = 0x08  # no cipher suite match with proposed algorithms
            return packet(0x06, 0x11, 0, 0, bytes(response[:8]))
        self.console_id = console_id
        self.privilege = privilege
        self.auth_algorithm, self.integrity_algorithm, self.confidentiality_algorithm = algorithms
        self.bmc_id = (int.from_bytes(os.urandom(4), 'little') | 1) & 0xffffffff
        response[8:12] = self.bmc_id.to_bytes(4, 'little')
        for index, algorithm in enumerate(algorithms):
            block = 12 + index * 8
            response[block] = index
            response[block + 3] = 8
            response[block + 4] = algorithm
        return packet(0x06, 0x11, 0, 0, bytes(response))

    def rakp1(self, payload):
        tag = payload[0]
        self.console_random = payload[8:24]
        role = payload[24]
        length = payload[27]
        name = payload[28:28 + length]
        self.bmc_random = os.urandom(16)
        self.guid = os.urandom(16)
        algorithm = {1: 'sha1', 3: 'sha256'}[self.auth_algorithm]
        self.algorithm = algorithm
        auth_code = digest(self.key, self.console_id.to_bytes(4, 'little') + self.bmc_id.to_bytes(4, 'little') +
                           self.console_random + self.bmc_random + self.guid + bytes([role, length]) + name,
                           algorithm)
        response = bytearray(40)
        response[0] = tag
        response[4:8] = self.console_id.to_bytes(4, 'little')
        response[8:24] = self.bmc_random
        response[24:40] = self.guid
        return packet(0x06, 0x13, 0, 0, bytes(response) + auth_code)

    def rakp3(self, payload):
        tag = payload[0]
        assert payload[1] == 0
        role, length = self.privilege, len(self.username)
        expected = digest(self.key, self.bmc_random + self.console_id.to_bytes(4, 'little') +
                          bytes([role, length]) + self.username, self.algorithm)
        assert payload[8:] == expected, 'RAKP3 auth code mismatch'
        self.sik = digest(self.key, self.console_random + self.bmc_random + bytes([role, length]) + self.username,
                          self.algorithm)
        self.k1 = digest(self.sik, b'\x01' * 20, self.algorithm)
        self.k2 = digest(self.sik, b'\x02' * 20, self.algorithm)
        integrity_size = 12 if self.integrity_algorithm == 1 else 16
        icv = digest(self.sik, self.console_random + self.bmc_id.to_bytes(4, 'little') + self.guid,
                     self.algorithm)[:integrity_size]
        response = bytearray(8)
        response[0] = tag
        response[4:8] = self.console_id.to_bytes(4, 'little')
        return packet(0x06, 0x15, 0, 0, bytes(response) + icv)

    def command(self, datagram, payload):
        completion = 0
        incoming_sequence = int.from_bytes(datagram[10:14], 'little')
        assert (incoming_sequence == 1 if not self.in_sequence else incoming_sequence > self.in_sequence), 'session sequence must start at one and reject replay'
        self.in_sequence = incoming_sequence
        length = int.from_bytes(datagram[14:16], 'little')
        if self.integrity_algorithm != 0:
            integrity_size = 12 if self.integrity_algorithm == 1 else 16
            pad = (4 - ((12 + length + 2) % 4)) % 4
            trailer = datagram[16 + length:16 + length + pad + 2]
            assert trailer[:pad] == b'\xff' * pad and trailer[pad] == pad and trailer[pad + 1] == 0x07
            expected = digest(self.k1, datagram[4:16 + length + pad + 2], self.algorithm)[:integrity_size]
            assert datagram[16 + length + pad + 2:] == expected, 'session integrity mismatch'
        assert datagram[5] & 0x80, 'expected encrypted payload'
        ciphertext = payload[16:]
        plain = aes_cbc(self.k2[:16], payload[:16], ciphertext, decrypt=True)
        pad = plain[-1]
        plain = plain[:-pad - 1] if pad else plain[:-1]
        _, netfn, _, _, sequence, command, data = parse_message(plain)
        if netfn == 0x06 and command == 0x3b:
            assert data == bytes([self.privilege])
            completion = getattr(self, 'privilege_completion', 0)
            response_data = bytes([getattr(self, 'granted_privilege', self.privilege)]) if not completion else b''
        elif netfn == 0x00 and command == 0x09:
            assert data in (bytes([0, 0, 0]), bytes([5, 0, 0]))
            response_data = bytes([1, data[0]]) + (bytes([self.boot_progress]) if data[0] == 0 else self.boot_flags)
        elif netfn == 0x00 and command == 0x08:
            self.boot_writes.append(data)
            if data[0] == 0:
                assert len(data) == 2
                self.boot_progress = data[1]
            else:
                assert data[0] == 5 and len(data) == 6 and self.boot_progress == 1
                if not self.boot_mismatch:
                    self.boot_flags = data[1:]
            response_data = b''
        elif netfn == 0x00 and command == 0x01:
            response_data = self.chassis_status_bytes
        elif netfn == 0x00 and command == 0x00:
            if self.chassis_caps_completion:
                completion = self.chassis_caps_completion
                response_data = b''
            elif self.chassis_caps is not None:
                response_data = self.chassis_caps
            else:
                completion = 0xc1
                response_data = b''
        elif netfn == 0x00 and command == 0x07:
            if self.restart_cause_completion:
                completion = self.restart_cause_completion
                response_data = b''
            elif self.restart_cause is not None:
                response_data = bytes(self.restart_cause)
            else:
                completion = 0xc1
                response_data = b''
        elif netfn == 0x00 and command == 0x02:
            self.power_action = data[0]
            self.power_requests = getattr(self, 'power_requests', 0) + 1
            if getattr(self, 'ignore_power_reply', False):
                return None
            response_data = b''
        elif netfn == 0x0a and command == 0x20:
            response_data = bytes([0x51, 0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            if hasattr(self, 'sensor_records'):
                response_data = response_data[:1] + len(self.sensor_records).to_bytes(2, 'little') + response_data[3:]
        elif netfn == 0x0a and command == 0x40:
            completion = self.sel_info_completion
            free_space = max(0, 0x1000 - len(self.sel_entries) * 16)
            response_data = bytes([0x51]) + len(self.sel_entries).to_bytes(2, 'little') + \
                free_space.to_bytes(2, 'little') + bytes([0x04, 0x03, 0x02, 0x01]) + \
                bytes(4) + bytes([0x40])
        elif netfn == 0x0a and command == 0x10:
            if self.fru_info_completion:
                completion = self.fru_info_completion
                response_data = b''
            elif data[0] in self.fru_devices:
                image = self.fru_devices[data[0]]
                response_data = len(image).to_bytes(2, 'little') + bytes([1 if data[0] in self.fru_word_access else 0])
            else:
                completion = 0xc7
                response_data = b''
        elif netfn == 0x0a and command == 0x11:
            fru_id, offset, count = data[0], int.from_bytes(data[1:3], 'little'), data[3]
            byte_offset = offset * 2 if fru_id in self.fru_word_access else offset
            self.fru_reads.append((fru_id, offset, count))
            image = self.fru_devices.get(fru_id, b'')
            pending = self.fru_read_failures.get(fru_id)
            if pending is not None and pending[0] >= byte_offset and pending[0] < byte_offset + max(count, 1):
                completion = pending[1]
                response_data = b''
            elif count > getattr(self, 'fru_max_request', 255):
                completion = 0xca
                response_data = b''
            elif byte_offset >= len(image):
                completion = 0xc9
                response_data = b''
            else:
                limit = self.fru_read_limit.get(fru_id, count)
                size = min(count, limit, len(image) - byte_offset)
                if fru_id in self.fru_word_access:
                    size &= ~1
                response_data = bytes([size]) + image[byte_offset:byte_offset + size]
        elif netfn == 0x0a and command == 0x42:
            self.sel_reservations += 1
            self.sel_reservation = (self.sel_reservation + 1) & 0xffff or 1
            response_data = self.sel_reservation.to_bytes(2, 'little')
        elif netfn == 0x0a and command == 0x43:
            if self.sel_bad_reservations:
                self.sel_bad_reservations -= 1
                completion = 0xc5
                response_data = b''
            else:
                requested = int.from_bytes(data[2:4], 'little')
                if int.from_bytes(data[0:2], 'little') != self.sel_reservation:
                    completion = 0xc5
                    response_data = b''
                elif requested == 0xffff:
                    completion = 0xca
                    response_data = b''
                else:
                    index = 0 if requested == 0 else next(
                        (i for i, r in enumerate(self.sel_entries) if int.from_bytes(r[:2], 'little') == requested), None)
                    if index is None:
                        completion = 0xca
                        response_data = b''
                    else:
                        record = self.sel_entries[index]
                        next_id = int.from_bytes(self.sel_entries[index + 1][:2], 'little') \
                            if index + 1 < len(self.sel_entries) else 0xffff
                        failure = self.sel_record_failures.get(requested)
                        if failure is not None:
                            completion = failure
                            response_data = b''
                        else:
                            size = self.sel_short_records.get(requested, len(record))
                            response_data = next_id.to_bytes(2, 'little') + record[:size]
        elif netfn == 0x0a and command == 0x22:
            response_data = bytes([0x34, 0x12])
        elif netfn == 0x0a and command == 0x23:
            record = bytearray(64)
            record[0:2] = (0).to_bytes(2, 'little')
            record[2], record[3], record[4] = 0x51, 0x01, 59
            body = memoryview(record)[5:]
            body[0], body[2], body[3], body[4] = 0x20, 0x23, 3, 1
            body[7], body[8], body[16] = 1, 1, 1
            body[19] = 1
            body[31:37] = b'\xff' * 6
            body[42] = 0xc3
            body[43:46] = b'CPU'
            response_data = (0xffff).to_bytes(2, 'little') + bytes(record)
            if hasattr(self, 'sensor_records'):
                requested = int.from_bytes(data[2:4], 'little')
                index = 0 if requested == 0 else next(i for i, r in enumerate(self.sensor_records) if int.from_bytes(r[:2], 'little') == requested)
                next_id = int.from_bytes(self.sensor_records[index + 1][:2], 'little') if index + 1 < len(self.sensor_records) else 0xffff
                response_data = next_id.to_bytes(2, 'little') + self.sensor_records[index]
        elif netfn == 0x04 and command == 0x2d:
            response_data = bytes([25, 0xc0])
            if hasattr(self, 'sensor_readings'):
                self.sensor_requests.append((command, data[0]))
                completion, response_data = self.sensor_readings[data[0]]
        elif netfn == 0x04 and command == 0x27:
            self.sensor_requests.append((command, data[0]))
            completion, response_data = self.sensor_thresholds[data[0]]
        elif netfn == 0x06 and command == 0x42:
            channel = data[0]
            if channel in self.channel_media:
                response_data = bytes([channel, self.channel_media[channel], 0x01, 0x40]) + bytes(5)
            else:
                completion = 0xcc
                response_data = b''
        elif netfn == 0x0c and command == 0x02:
            channel, selector, block = data[0], data[1], data[3]
            self.lan_requests.append((channel, selector, block))
            if channel in self.lan_drop_channels:
                return None
            if self.lan_completion is not None:
                completion = self.lan_completion
                response_data = b''
            else:
                if (channel, selector, block) in self.lan_params:
                    completion, response_data = self.lan_params[(channel, selector, block)]
                elif (channel, selector) in self.lan_params:
                    completion, response_data = self.lan_params[(channel, selector)]
                else:
                    completion = 0x80
                    response_data = b''
        elif command == 0x01 and netfn == 0x06:
            response_data = DEVICE_ID
        elif command == 0x3c:
            if getattr(self, 'ignore_close', False):
                return None
            assert int.from_bytes(data, 'little') == self.bmc_id
            completion = getattr(self, 'close_completion', 0)
            response_data = b''
        else:
            raise AssertionError(f'unexpected command netfn {netfn:#x} cmd {command:#x}')
        message = build_message(netfn + 1, command, response_data, sequence, completion)
        pad = 16 - ((len(message) + 1) % 16)
        if pad == 16:
            pad = 0
        padded = message + bytes(range(1, pad + 1)) + bytes([pad])
        iv = os.urandom(16)
        encrypted = iv + aes_cbc(self.k2[:16], iv, padded)
        header = bytearray(12)
        header[0] = 0x06
        header[1] = 0x00 | 0x80 | (0x40 if self.integrity_algorithm else 0)
        header[2:6] = self.console_id.to_bytes(4, 'little')
        header[6:10] = self.out_sequence.to_bytes(4, 'little')
        self.out_sequence = (self.out_sequence + 1) & 0xffffffff or 1
        header[10:12] = len(encrypted).to_bytes(2, 'little')
        integrity_pad = (4 - ((12 + len(encrypted) + 2) % 4)) % 4
        trailer = b'\xff' * integrity_pad + bytes([integrity_pad, 0x07])
        body = bytes(header) + encrypted + trailer
        auth = digest(self.k1, body, self.algorithm)[:12 if self.integrity_algorithm == 1 else 16]
        return b'\x06\x00\xff\x07' + body + auth


class Ipmi(unittest.TestCase):
    def test_session_privilege_rejection_and_mismatch(self):
        for attr, value, expected in [('privilege_completion', 0x81, 'authentication_failed'),
                                      ('granted_privilege', 2, 'protocol_error')]:
            with self.subTest(attr=attr), Bmc(SUITE_17) as bmc:
                setattr(bmc, attr, value)
                result = self.run_agent(bmc)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout)['status'], expected)

    def test_sensor_details_shared_event_only_and_partial_failure(self):
        def record(record_id, kind, number, owner=0x20):
            body = bytearray(46 if kind == 1 else 29 if kind == 2 else 14)
            body[0:5] = bytes([owner, 0, number, 7, 0x81])
            if kind == 1:
                body[7], body[8], body[16], body[19] = 1, 1, 1, 1
                body[10], body[12] = 0x70, 0x70
                body[42:46] = b'\xc3CPU'
            elif kind == 2:
                body[7], body[8] = 8, 0x6f
                body[13:15] = b'\xff\x7f'
                body[18:20] = bytes([0x13, 0x80 | 25])
                body[26:29] = b'\xc2PS'
            else:
                body[5], body[6] = 0x0f, 0x6f
                body[11:14] = b'\xc2FW'
            return record_id.to_bytes(2, 'little') + bytes([0x51, kind, len(body)]) + body
        with Bmc(SUITE_17) as bmc:
            bmc.sensor_records = [record(10, 1, 35), record(11, 2, 40), record(12, 3, 60, 0x41), record(13, 1, 70, 0x30), record(14, 1, 71)]
            bmc.sensor_readings = {35: (0, bytes([0, 0xc0, 0x10])), 40: (0, bytes([0, 0xc0, 1, 0x81])), 41: (0, bytes([0, 0xe0])), 42: (0, bytes([0, 0xc0, 0])), 71: (0, b'\x01')}
            bmc.sensor_thresholds = {35: (0, bytes([0x11, 0, 0, 0, 0, 255, 0])), 71: (0xd4, b'')}
            bmc.sensor_requests = []
            result = self.run_agent(bmc, '--command', 'sensor-details')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            rows = json.loads(result.stdout)['sensors']
            self.assertEqual(len(rows), 7)
            self.assertEqual(rows[0]['reading'], 0)
            self.assertEqual(rows[0]['thresholds'][4]['reading'], 255)
            self.assertEqual(rows[0]['health'], 3)
            self.assertEqual([r['id'] for r in rows[1:4]], ['PSZ', 'PSAA', 'PSAB'])
            self.assertEqual(rows[1]['discrete_states'], 0x101)
            self.assertEqual(rows[2]['fields']['states']['state'], 'unavailable')
            self.assertEqual(rows[3]['discrete_valid_mask'], 255)
            for r in rows[4:6]: self.assertEqual(r['fields']['reading']['state'], 'unsupported')
            self.assertEqual(rows[6]['fields']['reading']['status'], 'protocol_error')
            self.assertEqual(rows[6]['fields']['thresholds']['status'], 'authentication_failed')
            self.assertFalse(any(number in (60, 70) for _, number in bmc.sensor_requests))

    def test_sensor_optional_thresholds_and_permission(self):
        for code, exit_code, expected in [(0xc1, 0, 'unsupported'), (0xd4, 1, 'authentication_failed')]:
            with self.subTest(code=code), Bmc(SUITE_17) as bmc:
                bmc.sensor_requests = []
                bmc.sensor_thresholds = {0x23: (code, b'')}
                result = self.run_agent(bmc, '--command', 'sensor-details')
                self.assertEqual(result.returncode, exit_code, result.stdout + result.stderr)
                row = json.loads(result.stdout)['sensors'][0]
                self.assertEqual(row['reading'], 25)
                self.assertEqual(row['fields']['thresholds']['status'], expected)

    def test_sel_read_only_records(self):
        first = sel_record(0x0001, 0x02, sel_event_payload(0x345678, bytes(range(1, 11))))
        second = sel_record(0x0002, 0xc0, bytes(range(0xa0, 0xad)))
        third = sel_record(0x0100, 0xe1, sel_event_payload(0x010203, bytes(range(0x20, 0x2a))))
        with Bmc(SUITE_17) as bmc:
            bmc.sel_entries = [first, second, third]
            result = self.run_agent(bmc, '--command', 'sel')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['sel_status'], 'ok')
            sel = row['sel']
            self.assertEqual(sel['entries_in_use'], 3)
            self.assertFalse(sel['overflow'])
            self.assertEqual(sel['free_space'], 0x1000 - 48)
            entries = sel['entries']
            self.assertEqual(len(entries), 3)
            self.assertEqual(entries[0]['record_id'], 1)
            self.assertEqual(entries[0]['record_type'], 0x02)
            self.assertEqual(entries[0]['timestamp'], 0x345678)
            self.assertEqual(entries[0]['raw'], list(first))
            self.assertEqual(entries[0]['status'], 'ok')
            self.assertEqual(entries[1]['timestamp'], None)
            self.assertEqual(entries[1]['raw'], list(second))
            self.assertEqual(entries[2]['record_id'], 0x100)
            self.assertEqual(entries[2]['timestamp'], 0x010203)
            self.assertEqual(bmc.sel_reservations, 1)

    def test_sel_empty(self):
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--command', 'sel')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['sel_status'], 'ok')
            self.assertEqual(row['sel']['entries_in_use'], 0)
            self.assertEqual(row['sel']['entries'], [])
            self.assertEqual(bmc.sel_reservations, 0)

    def test_sel_reservation_invalidation_retries(self):
        records = [sel_record(0x0001, 0x02, sel_event_payload(1, bytes(10))),
                   sel_record(0x0002, 0x02, sel_event_payload(2, bytes(10)))]
        with Bmc(SUITE_17) as bmc:
            bmc.sel_entries = records
            bmc.sel_bad_reservations = 1
            result = self.run_agent(bmc, '--command', 'sel')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            entries = json.loads(result.stdout)['sel']['entries']
            self.assertEqual(len(entries), 2)
            self.assertEqual(bmc.sel_reservations, 2)

    def test_sel_partial_record_errors(self):
        records = [sel_record(0x0001, 0x02, sel_event_payload(1, bytes(10))),
                   sel_record(0x0002, 0x02, sel_event_payload(2, bytes(10))),
                   sel_record(0x0003, 0x02, sel_event_payload(3, bytes(10)))]
        with self.subTest(mode='completion failure'):
            with Bmc(SUITE_17) as bmc:
                bmc.sel_entries = records
                bmc.sel_record_failures = {0x0002: 0xca}
                result = self.run_agent(bmc, '--command', 'sel')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual(row['sel_status'], 'protocol_error')
                entries = row['sel']['entries']
                self.assertEqual(len(entries), 2)
                self.assertEqual(entries[0]['record_id'], 1)
                self.assertEqual(entries[0]['status'], 'ok')
                self.assertEqual(entries[1]['record_id'], 2)
                self.assertEqual(entries[1]['status'], 'protocol_error')
                self.assertEqual(entries[1]['raw'], [])
        with self.subTest(mode='truncated record continues'):
            with Bmc(SUITE_17) as bmc:
                bmc.sel_entries = records
                bmc.sel_short_records = {0x0002: 10}
                result = self.run_agent(bmc, '--command', 'sel')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual(row['sel_status'], 'protocol_error')
                entries = row['sel']['entries']
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[1]['status'], 'protocol_error')
                self.assertEqual(entries[1]['raw'], list(records[1][:10]))
                self.assertEqual(entries[2]['record_id'], 3)
                self.assertEqual(entries[2]['status'], 'ok')

    def test_sel_info_failures(self):
        for code, expected in [(0xc1, 'unsupported'), (0xd4, 'authentication_failed')]:
            with self.subTest(code=code):
                with Bmc(SUITE_17) as bmc:
                    bmc.sel_info_completion = code
                    result = self.run_agent(bmc, '--command', 'sel')
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    row = json.loads(result.stdout)
                    self.assertEqual(row['sel_status'], expected)
                    self.assertEqual(row['sel']['entries'], [])

    def test_sel_entry_limit(self):
        records = [sel_record(0x1000 + i, 0x02, sel_event_payload(i, bytes(10))) for i in range(133)]
        with Bmc(SUITE_17) as bmc:
            bmc.sel_entries = records
            result = self.run_agent(bmc, '--command', 'sel')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['sel_status'], 'limit_exceeded')
            self.assertTrue(row['sel']['truncated'])
            self.assertEqual(len(row['sel']['entries']), 128)
            self.assertEqual(row['sel']['entries'][127]['record_id'], 0x1000 + 127)

    def test_fru_reduces_rejected_read_size(self):
        with Bmc(SUITE_17) as bmc:
            bmc.fru_devices = {0: standard_fru_image()}
            bmc.fru_max_request = 16
            result = self.run_agent(bmc, '--command', 'fru')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['fru_status'], 'ok')
            self.assertTrue(any(count == 32 for _, _, count in bmc.fru_reads))
            self.assertTrue(any(count == 16 for _, _, count in bmc.fru_reads))

    def test_fru_standard_image(self):
        with Bmc(SUITE_17) as bmc:
            bmc.fru_devices = {0: standard_fru_image()}
            result = self.run_agent(bmc, '--command', 'fru')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['fru_status'], 'ok')
            self.assertEqual(len(row['fru_devices']), 1)
            device = row['fru_devices'][0]
            self.assertEqual(device['fru_id'], 0)
            self.assertFalse(device['word_access'])
            self.assertEqual(device['status'], 'ok')
            self.assertEqual(device['chassis']['part_number']['text'], 'CHAS-CASE')
            self.assertEqual(device['chassis']['serial_number']['text'], 'CHASSN1')
            self.assertEqual(device['chassis']['type'], 0x17)
            self.assertEqual(device['board']['manufacturer']['text'], 'AcmeBoard')
            self.assertEqual(device['board']['product']['text'], 'BoardOne')
            self.assertEqual(device['board']['serial']['text'], 'BSN-77')
            self.assertEqual(device['board']['part_number']['text'], 'BP-1')
            self.assertEqual(device['board']['language'], 0)
            self.assertEqual(device['board']['mfg_date'], 0x60b0a0)
            self.assertEqual(device['product']['manufacturer']['text'], 'Acme')
            self.assertEqual(device['product']['name']['text'], 'Server')
            self.assertEqual(device['product']['asset_tag']['text'], 'A456')
            file_id = device['product']['file_id']
            self.assertEqual(file_id['status'], 'unsupported')
            self.assertEqual(device['board']['file_id']['type'], 0)
            self.assertEqual(device['board']['file_id']['raw'], [2])
            self.assertEqual(device['multi_record']['status'], 'unsupported')
            self.assertEqual(len(device['multi_record']['raw']), 8)

    def test_fru_fru_id_selection(self):
        image = standard_fru_image()
        with Bmc(SUITE_17) as bmc:
            bmc.fru_devices = {0: image, 1: image}
            result = self.run_agent(bmc, '--command', 'fru', '--fru-id', '1')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['fru_status'], 'ok')
            self.assertEqual([d['fru_id'] for d in row['fru_devices']], [1])
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--command', 'fru', '--fru-id', '5')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['fru_status'], 'unsupported')

    def test_fru_bad_headers_and_area_checksum(self):
        with self.subTest(mode='empty header'):
            with Bmc(SUITE_17) as bmc:
                bmc.fru_devices = {0: bytes([1, 0, 0, 0, 0, 0, 0, 0xff])}
                result = self.run_agent(bmc, '--command', 'fru')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                device = json.loads(result.stdout)['fru_devices'][0]
                self.assertFalse(device['chassis']['present'])
                self.assertFalse(device['product']['present'])
                self.assertEqual(device['multi_record']['length'], 0)
        with self.subTest(mode='bad header checksum'):
            with Bmc(SUITE_17) as bmc:
                bmc.fru_devices = {0: bytes([1, 0, 0, 0, 0, 0, 0, 0x7f])}
                result = self.run_agent(bmc, '--command', 'fru')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['fru_status'], 'protocol_error')
        with self.subTest(mode='bad product checksum keeps verified areas'):
            with Bmc(SUITE_17) as bmc:
                chassis = fru_area(bytes([0x17]) + fru_tl(b'CHAS-CASE') + fru_tl(b'CHASSN1') + b'\xc1')
                board = fru_area(bytes([0]) + bytes(3) + fru_tl(b'AcmeBoard') + fru_tl(b'BoardOne') +
                                 fru_tl(b'BSN-77') + fru_tl(b'BP-1') + fru_tl(b'\x02', encoding=0) + b'\xc1')
                product = bytearray(fru_area(bytes([0]) + fru_tl(b'Acme') + b'\xc1'))
                product[3] ^= 0x40
                bmc.fru_devices = {0: fru_image(chassis=chassis, board=board, product=bytes(product))}
                result = self.run_agent(bmc, '--command', 'fru')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                device = json.loads(result.stdout)['fru_devices'][0]
                self.assertEqual(device['status'], 'protocol_error')
                self.assertEqual(device['chassis']['status'], 'ok')
                self.assertEqual(device['chassis']['part_number']['text'], 'CHAS-CASE')
                self.assertEqual(device['board']['status'], 'ok')
                self.assertEqual(device['board']['manufacturer']['text'], 'AcmeBoard')
                self.assertEqual(device['product']['status'], 'protocol_error')

    def test_fru_word_access_and_short_reads(self):
        image = standard_fru_image()
        if len(image) % 2:
            image += b'\x00'
        with Bmc(SUITE_17) as bmc:
            bmc.fru_devices = {0: image}
            bmc.fru_word_access = {0}
            bmc.fru_read_limit = {0: 7}
            result = self.run_agent(bmc, '--command', 'fru')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            device = json.loads(result.stdout)['fru_devices'][0]
            self.assertTrue(device['word_access'])
            self.assertEqual(device['product']['serial']['text'], 'S123')
            self.assertGreater(len(bmc.fru_reads), 8)
            for _, _, count in bmc.fru_reads:
                self.assertEqual(count % 2, 0)

    def test_fru_partial_read_failure(self):
        chassis = fru_area(bytes([0x17]) + fru_tl(b'CHAS-CASE') + fru_tl(b'CHASSN1') + b'\xc1')
        product = fru_area(bytes([0]) + fru_tl(b'Acme') + fru_tl(b'Server') + b'\xc1')
        image = fru_image(chassis=chassis, product=product)
        product_offset = image.index(product)
        with Bmc(SUITE_17) as bmc:
            bmc.fru_devices = {0: image}
            bmc.fru_read_failures = {0: (product_offset + 4, 0xd4)}
            result = self.run_agent(bmc, '--command', 'fru')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            device = json.loads(result.stdout)['fru_devices'][0]
            self.assertEqual(device['status'], 'authentication_failed')
            self.assertEqual(device['chassis']['status'], 'ok')
            self.assertEqual(device['chassis']['part_number']['text'], 'CHAS-CASE')
            self.assertEqual(device['product']['status'], 'protocol_error')

    def test_fru_info_failures(self):
        for code, expected in [(0xc1, 'unsupported'), (0xd4, 'authentication_failed')]:
            with self.subTest(code=code):
                with Bmc(SUITE_17) as bmc:
                    bmc.fru_info_completion = code
                    bmc.fru_devices = {0: standard_fru_image()}
                    result = self.run_agent(bmc, '--command', 'fru')
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    row = json.loads(result.stdout)
                    self.assertEqual(row['fru_status'], expected)
                    self.assertEqual(row['fru_devices'], [])

    def test_fru_device_limit(self):
        devices = {i: standard_fru_image() for i in range(16)}
        with Bmc(SUITE_17) as bmc:
            bmc.fru_devices = devices
            result = self.run_agent(bmc, '--command', 'fru')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['fru_status'], 'limit_exceeded')
            self.assertEqual(len(row['fru_devices']), 16)

    def test_chassis_status_without_optional_front_panel_byte(self):
        with Bmc(SUITE_17) as bmc:
            bmc.chassis_status_bytes = bytes([1, 0, 0])
            result = self.run_agent(bmc, '--command', 'power-status')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['power_state'], 'on')

    def test_chassis_readonly_full(self):
        with Bmc(SUITE_17) as bmc:
            bmc.chassis_status_bytes = bytes([0x41, 0x10, 0x5b, 0x00])
            bmc.chassis_caps = bytes([0x0f, 0x30, 0x20, 0x42, 0x10, 0x52])
            bmc.restart_cause = bytes([0x06, 0x0e])
            result = self.run_agent(bmc, '--command', 'chassis')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['power_state'], 'on')
            self.assertEqual(row['power_restore_policy'], 'always-on')
            self.assertEqual(row['last_power_event'], 0x10)
            self.assertTrue(row['intrusion_active'])
            self.assertTrue(row['front_panel_lockout'])
            self.assertFalse(row['drive_fault'])
            self.assertTrue(row['fan_fault'])
            self.assertEqual(row['identify_state'], 'temporary')
            self.assertNotIn('acpi_power_state', row)
            caps = row['capabilities']
            self.assertEqual(caps['status'], 'ok')
            self.assertTrue(caps['intrusion_sensor'])
            self.assertTrue(caps['front_panel_lockout'])
            self.assertTrue(caps['diagnostic_interrupt'])
            self.assertTrue(caps['power_interlock'])
            self.assertEqual(caps['fru_device_address'], 0x30)
            self.assertEqual(caps['sdr_device_address'], 0x20)
            self.assertEqual(caps['sel_device_address'], 0x42)
            self.assertEqual(caps['sm_device_address'], 0x10)
            self.assertEqual(caps['bridge_device_address'], 0x52)
            restart = row['restart_cause']
            self.assertEqual(restart['status'], 'ok')
            self.assertEqual(restart['cause'], 6)
            self.assertEqual(restart['cause_name'], 'always-restore-policy')
            self.assertEqual(restart['channel'], 0x0e)

    def test_chassis_caps_zero_and_no_bridge(self):
        with Bmc(SUITE_17) as bmc:
            bmc.chassis_caps = bytes([0x00, 0x00, 0x00, 0x00, 0x00])
            result = self.run_agent(bmc, '--command', 'chassis')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            caps = json.loads(result.stdout)['capabilities']
            self.assertFalse(caps['intrusion_sensor'])
            self.assertFalse(caps['front_panel_lockout'])
            self.assertFalse(caps['diagnostic_interrupt'])
            self.assertFalse(caps['power_interlock'])
            self.assertEqual(caps['fru_device_address'], 0)
            self.assertNotIn('bridge_device_address', caps)

    def test_chassis_power_restore_policy_encodings(self):
        for byte, expected in [(0x00, 'always-off'), (0x20, 'previous'), (0x40, 'always-on'), (0x60, 'unknown')]:
            with self.subTest(policy=expected):
                with Bmc(SUITE_17) as bmc:
                    bmc.chassis_status_bytes = bytes([byte, 0x00, 0x00, 0x00])
                    result = self.run_agent(bmc, '--command', 'chassis')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    row = json.loads(result.stdout)
                    self.assertEqual(row['power_state'], 'off')
                    self.assertEqual(row['power_restore_policy'], expected)

    def test_chassis_identify_states(self):
        for misc, expected in [(0x40, 'off'), (0x50, 'temporary'), (0x60, 'indefinite'), (0x70, None)]:
            with self.subTest(misc=hex(misc)):
                with Bmc(SUITE_17) as bmc:
                    bmc.chassis_status_bytes = bytes([0x01, 0x00, misc, 0x00])
                    result = self.run_agent(bmc, '--command', 'chassis')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    row = json.loads(result.stdout)
                    if expected is None:
                        self.assertNotIn('identify_state', row)
                    else:
                        self.assertEqual(row['identify_state'], expected)

    def test_chassis_restart_cause_values(self):
        for cause in (0, 2, 4, 5, 7, 8, 10, 11):
            with self.subTest(cause=cause):
                with Bmc(SUITE_17) as bmc:
                    bmc.restart_cause = bytes([cause, 0x01])
                    result = self.run_agent(bmc, '--command', 'chassis')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    restart = json.loads(result.stdout)['restart_cause']
                    self.assertEqual(restart['cause'], cause)
                    self.assertNotEqual(restart['cause_name'], 'reserved')
        with Bmc(SUITE_17) as bmc:
            bmc.restart_cause = bytes([0x0d, 0x00])
            result = self.run_agent(bmc, '--command', 'chassis')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            restart = json.loads(result.stdout)['restart_cause']
            self.assertEqual(restart['cause'], 0x0d)
            self.assertEqual(restart['cause_name'], 'reserved')

    def test_chassis_subcommand_failures(self):
        with self.subTest(mode='capabilities unsupported keeps power info'):
            with Bmc(SUITE_17) as bmc:
                result = self.run_agent(bmc, '--command', 'chassis')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual(row['power_state'], 'on')
                self.assertEqual(row['capabilities']['status'], 'unsupported')
                self.assertEqual(row['restart_cause']['status'], 'unsupported')
        with self.subTest(mode='capabilities insufficient privilege'):
            with Bmc(SUITE_17) as bmc:
                bmc.chassis_caps_completion = 0xd4
                result = self.run_agent(bmc, '--command', 'chassis')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual(row['capabilities']['status'], 'authentication_failed')
                self.assertEqual(row['restart_cause']['status'], 'unsupported')
        with self.subTest(mode='capabilities short response'):
            with Bmc(SUITE_17) as bmc:
                bmc.chassis_caps = bytes([0x01, 0x20, 0x20])
                result = self.run_agent(bmc, '--command', 'chassis')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual(row['capabilities']['status'], 'protocol_error')
                self.assertEqual(row['power_state'], 'on')
        with self.subTest(mode='status short response'):
            with Bmc(SUITE_17) as bmc:
                bmc.chassis_status_bytes = bytes([0x01, 0x00])
                result = self.run_agent(bmc, '--command', 'chassis')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['chassis_status'], 'protocol_error')
        with self.subTest(mode='restart cause insufficient privilege'):
            with Bmc(SUITE_17) as bmc:
                bmc.restart_cause_completion = 0xd4
                result = self.run_agent(bmc, '--command', 'chassis')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['restart_cause']['status'], 'authentication_failed')

    def test_lan_readonly_full(self):
        with Bmc(SUITE_17) as bmc:
            bmc.channel_media[1] = 0x04
            revision = bytes([0x11])
            bmc.lan_params = {
                (1, 0): (0, revision + bytes([0])),
                (1, 1): (0, revision + bytes([0x1e])),
                (1, 2): (0, revision + bytes([0x11, 0x11, 0x11, 0x11, 0x11])),
                (1, 3): (0, revision + bytes([192, 168, 1, 10])),
                (1, 4): (0, revision + bytes([2])),
                (1, 5): (0, revision + bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
                (1, 6): (0, revision + bytes([255, 255, 255, 0])),
                (1, 7): (0, revision + bytes([0x40, 0x40, 0x00])),
                (1, 8): (0, revision + bytes([0x02, 0x26])),
                (1, 9): (0, revision + bytes([0x02, 0x27])),
                (1, 10): (0, revision + bytes([0x03])),
                (1, 11): (0, revision + bytes([0x00])),
                (1, 12): (0, revision + bytes([192, 168, 1, 1])),
                (1, 13): (0, revision + bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
                (1, 14): (0, revision + bytes([192, 168, 2, 1])),
                (1, 15): (0, revision + bytes(6)),
                (1, 17): (0, revision + bytes([4])),
                (1, 18): (0, revision + bytes([0x00, 0x00, 0x00, 0x00])),
                (1, 19): (0, revision + bytes([0x81, 0, 0, 0]) + bytes([192, 168, 1, 2]) + bytes(6)),
                (1, 20): (0, revision + bytes([0x2c, 0x81])),
                (1, 21): (0, revision + bytes([0x05])),
                (1, 22): (0, revision + bytes([17])),
                (1, 23, 0): (0, revision + bytes([16]) + bytes(range(16))),
                (1, 23, 1): (0, revision + bytes([1, 0xc0])),
                (1, 24): (0, revision + bytes([0x00]) + bytes([0xa4, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00])),
            }
            result = self.run_agent(bmc, '--command', 'lan')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['channel_count'], 1)
            self.assertEqual(row['lan_channel_count'], 1)
            self.assertEqual(len(row['lan_channels']), 1)
            channel = row['lan_channels'][0]
            self.assertEqual(channel['channel'], 1)
            self.assertTrue(channel['is_lan'])
            self.assertEqual(channel['status'], 'ok')
            params = {entry['selector']: entry for entry in channel['parameters']}
            self.assertNotIn(16, params)
            self.assertEqual(params[0]['value'], 'not-in-progress')
            self.assertEqual(params[0]['revision'], 0x11)
            self.assertEqual(params[3]['value'], '192.168.1.10')
            self.assertEqual(params[4]['value'], 'dhcp')
            self.assertEqual(params[5]['value'], 'aa:bb:cc:dd:ee:ff')
            self.assertEqual(params[6]['value'], '255.255.255.0')
            self.assertEqual(params[12]['value'], '192.168.1.1')
            self.assertEqual(params[13]['value'], '11:22:33:44:55:66')
            self.assertTrue(params[20]['enabled'])
            self.assertEqual(params[20]['vlan_id'], 300)
            self.assertEqual(params[22]['value'], 17)
            self.assertEqual(params[23]['value'], list(range(16)) + [0xc0])
            self.assertEqual(params[24]['value'], [4, 10, 4, 4, 3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0])
            self.assertEqual(params[23]['revision'], 0x11)
            self.assertIn((1, 23, 1), bmc.lan_requests)
            self.assertEqual(bmc.power_action, None)

    def test_lan_unsupported_short_read_and_trim(self):
        with Bmc(SUITE_17) as bmc:
            bmc.channel_media[1] = 0x04
            revision = bytes([0x11])
            bmc.lan_params = {
                (1, 0): (0, revision + bytes([0])),
                (1, 3): (0, revision + bytes([10, 0, 0])),
                (1, 4): (0, revision),
                (1, 20): (0x80, b''),
                (1, 22): (0, revision + bytes([5])),
                (1, 23, 0): (0, revision + bytes([16]) + bytes(range(16))),
            }
            result = self.run_agent(bmc, '--command', 'lan')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            channel = json.loads(result.stdout)['lan_channels'][0]
            self.assertEqual(channel['status'], 'ok')
            params = {entry['selector']: entry for entry in channel['parameters']}
            self.assertEqual(params[20]['status'], 'unsupported')
            self.assertEqual(params[20]['completion_code'], 0x80)
            self.assertTrue(params[3]['short_read'])
            self.assertNotIn('value', params[3])
            self.assertNotIn('value', params[4])
            self.assertNotIn('short_read', params[4])
            self.assertEqual(params[23]['value'], list(range(5)))
            self.assertNotIn((1, 23, 1), bmc.lan_requests)

    def test_lan_channel_boundaries(self):
        with Bmc(SUITE_17) as bmc:
            revision = bytes([0x11])
            bmc.channel_media = {1: 0x04, 2: 0x05, 3: 0x06, 0x0c: 0x04, 0x0d: 0x04, 0x0e: 0x04}
            bmc.lan_params = {
                (1, 4): (0, revision + bytes([1])),
                (2, 4): (0, revision + bytes([2])),
            }
            result = self.run_agent(bmc, '--command', 'lan')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['channel_count'], 3)
            self.assertEqual(row['lan_channel_count'], 2)
            channels = {entry['channel']: entry for entry in row['lan_channels']}
            self.assertEqual(sorted(channels), [1, 2, 3])
            self.assertTrue(channels[1]['is_lan'])
            self.assertTrue(channels[2]['is_lan'])
            self.assertFalse(channels[3]['is_lan'])
            self.assertNotIn('parameters', channels[3])
            self.assertFalse(any(channel >= 0x0c for channel, _, _ in bmc.lan_requests))
            params = {entry['selector']: entry for entry in channels[1]['parameters']}
            self.assertEqual(params[4]['value'], 'static')
            params = {entry['selector']: entry for entry in channels[2]['parameters']}
            self.assertEqual(params[4]['value'], 'dhcp')

    def test_lan_permission_timeout_and_no_lan(self):
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--command', 'lan')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['channel_count'], 0)
            self.assertEqual(row['lan_channel_count'], 0)
            self.assertEqual(row['lan_channels'], [])
        with Bmc(SUITE_17) as bmc:
            bmc.channel_media[1] = 0x04
            bmc.lan_completion = 0xd4
            result = self.run_agent(bmc, '--command', 'lan')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            channel = json.loads(result.stdout)['lan_channels'][0]
            self.assertEqual(channel['status'], 'authentication_failed')
            for entry in channel['parameters']:
                self.assertEqual(entry['status'], 'authentication_failed')
        with Bmc(SUITE_17) as bmc:
            bmc.channel_media[1] = 0x04
            bmc.lan_drop_channels.add(1)
            result = self.run_agent(bmc, '--command', 'lan')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            channel = json.loads(result.stdout)['lan_channels'][0]
            self.assertEqual(channel['status'], 'timeout')

    def test_verbose_ipmi_command_logging(self):
        with Bmc(SUITE_17) as bmc:
            environment = dict(os.environ, BC_BMC_USERNAME=USERNAME, BC_BMC_PASSWORD=PASSWORD)
            result = subprocess.run([AGENT, 'ipmi', '--log-level', 'verbose', '--log-categories', 'ipmi',
                                     '--host', '127.0.0.1', '--port', str(bmc.port), '--timeout-ms', '500',
                                     '--retries', '2', '--command', 'power-status'],
                                    env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('event=ipmi.command.request', result.stderr)
            self.assertIn('netfn=0x00 cmd=0x01', result.stderr)
            self.assertIn('data=', result.stderr)
            self.assertNotIn(PASSWORD, result.stderr)
            self.assertNotIn(USERNAME, result.stderr)
        with Bmc(SUITE_17) as bmc:
            environment = dict(os.environ, BC_BMC_USERNAME=USERNAME, BC_BMC_PASSWORD=PASSWORD)
            result = subprocess.run([AGENT, 'ipmi', '--log-level', 'verbose', '--log-categories', 'ipmi',
                                     '--host', '127.0.0.1', '--port', str(bmc.port), '--timeout-ms', '500',
                                     '--retries', '2', '--command', 'sensors'],
                                    env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertRegex(result.stderr, r'cmd=0x23 data_len=6 data=[0-9a-f]+')
            self.assertNotIn(PASSWORD, result.stderr)
            self.assertNotIn(USERNAME, result.stderr)

    def run_agent(self, bmc, *arguments):
        environment = dict(os.environ, BC_BMC_USERNAME=USERNAME, BC_BMC_PASSWORD=PASSWORD)
        return subprocess.run([AGENT, 'ipmi', '--host', '127.0.0.1', '--port', str(bmc.port),
                               '--timeout-ms', '500', '--retries', '2', *arguments],
                              env=environment, capture_output=True, text=True, timeout=20)

    def test_remote_boot_selector_roundtrip(self):
        for name, target, selector in [('remote-cd', 7, 8), ('remote-fd', 8, 7),
                                      ('remote-disk', 9, 11), ('remote-primary', 10, 9), ('floppy', 11, 15)]:
            with self.subTest(name=name), Bmc(SUITE_17) as bmc:
                result = self.run_agent(bmc, '--boot-once', name, '--boot-mode', 'legacy')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['boot']['target'], target)
                self.assertEqual(bmc.boot_writes, [bytes([0, 1]), bytes([5, 0x80, selector << 2, 0, 0, 0]), bytes([0, 0])])
                self.assertIsNone(bmc.power_action)

    def test_boot_once_and_cleanup(self):
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--boot-once', 'cd', '--boot-mode', 'uefi')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['boot']['target'], 3)
            self.assertEqual(row['boot']['flags'] & 3, 1)
            self.assertEqual(bmc.boot_progress, 0)
            self.assertEqual(bmc.boot_writes, [bytes([0, 1]), bytes([5, 0xa0, 0x14, 0, 0, 0]), bytes([0, 0])])
            self.assertIsNone(bmc.power_action)
        with Bmc(SUITE_17) as bmc:
            bmc.boot_mismatch = True
            result = self.run_agent(bmc, '--boot-once', 'cd', '--boot-mode', 'legacy')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['command_status'], 'outcome_unknown')
            self.assertEqual(bmc.boot_progress, 0)
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--boot-once', 'cd')
            self.assertEqual(json.loads(result.stdout)['command_status'], 'confirmation_required')
            self.assertEqual(bmc.boot_writes, [])
        with Bmc(SUITE_17) as bmc:
            bmc.boot_progress = 1
            result = self.run_agent(bmc, '--boot-once', 'cd', '--boot-mode', 'uefi')
            self.assertEqual(json.loads(result.stdout)['command_status'], 'busy')
            self.assertEqual(bmc.boot_writes, [])

    def test_boot_lost_acquire_is_not_retried_or_released(self):
        class LostAcquireBmc(Bmc):
            def handle(self, datagram):
                before = len(self.boot_writes)
                reply = super().handle(datagram)
                if len(self.boot_writes) > before and self.boot_writes[-1] == bytes([0, 1]):
                    return None
                return reply

        with LostAcquireBmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--boot-once', 'cd', '--boot-mode', 'uefi')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['command_status'], 'outcome_unknown')
            self.assertEqual(bmc.boot_writes, [bytes([0, 1])])
            self.assertEqual(bmc.boot_progress, 1)

    def test_boot_expired_business_budget_still_releases_owned_lock(self):
        class LostWriteBmc(Bmc):
            def handle(self, datagram):
                before = len(self.boot_writes)
                reply = super().handle(datagram)
                if len(self.boot_writes) > before and self.boot_writes[-1][0] == 5:
                    return None
                return reply

        with LostWriteBmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--boot-once', 'cd', '--boot-mode', 'uefi',
                                    '--budget-ms', '800', '--timeout-ms', '5000')
            row = json.loads(result.stdout)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(row['command_status'], 'outcome_unknown')
            self.assertEqual(row['cleanup_status'], 'ok')
            self.assertEqual(bmc.boot_progress, 0)
            self.assertEqual(bmc.boot_writes,
                             [bytes([0, 1]), bytes([5, 0xa0, 0x14, 0, 0, 0]), bytes([0, 0])])

    def test_suite17_session_device_id_and_close(self):
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['cipher_suite'], 17)
            self.assertEqual(row['auth'], 'hmac-sha256')
            self.assertEqual(row['integrity'], 'hmac-sha256-128')
            self.assertEqual(row['confidentiality'], 'aes-cbc-128')
            self.assertEqual(row['device_id'], 0x20)
            self.assertEqual(row['firmware'], '1.15')
            self.assertEqual(row['manufacturer_id'], 0x000157)
            self.assertEqual(row['product_id'], 0x1234)
            self.assertEqual(row['completion_code'], 0)
            self.assertEqual(row['close'], 'ok')

    def test_ilom_handshake_padding_and_initial_zero_sequence(self):
        class IlomBmc(Bmc):
            def __init__(self):
                super().__init__(SUITE_3)
                self.out_sequence = 0

            def handle(self, datagram):
                reply = super().handle(datagram)
                if reply and reply[5] in (0x11, 0x13, 0x15):
                    body = reply[16:] + b'\xa5'
                    return packet(6, reply[5], 0, 0, body)
                return reply

        with IlomBmc() as bmc:
            result = self.run_agent(bmc, '--confirm-suite3')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)['device_id'], 0x20)
            self.assertEqual(json.loads(result.stdout)['close'], 'ok')

    def test_suite3_requires_explicit_confirmation(self):
        with Bmc(SUITE_3) as bmc:
            result = self.run_agent(bmc, '--allow-suite3')
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'confirmation_required')
            self.assertEqual(row['cipher_suite'], 3)
        with Bmc(SUITE_3) as bmc:
            result = self.run_agent(bmc, '--confirm-suite3')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['cipher_suite'], 3)
            self.assertEqual(row['auth'], 'hmac-sha1')
            self.assertEqual(row['integrity'], 'hmac-sha1-96')
            self.assertEqual(row['device_id'], 0x20)

    def test_chassis_status_sensors_and_power_action(self):
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--command', 'power-status')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)['power_state'], 'on')
            bmc.suites = SUITE_17
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--command', 'sensors')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['sensor_count'], 1)
            self.assertEqual(row['sensors'][0]['number'], 0x23)
            self.assertEqual(row['sensors'][0]['id'], 'CPU')
            self.assertEqual(row['sensors'][0]['reading'], 25.0)
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--action', 'soft-off')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)['completion_code'], 0)
            self.assertEqual(bmc.power_action, 5)

    def test_capabilities_and_legacy_detection(self):
        with Bmc(SUITE_17) as bmc:
            result = self.run_agent(bmc, '--command', 'capabilities')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertTrue(row['chassis_status'])
            self.assertTrue(row['sdr'])
            self.assertTrue(row['sel'])
            self.assertFalse(row['fru'])
            self.assertEqual(row['sdr_record_count'], 1)
            self.assertEqual(row['sel_record_count'], 0)
            self.assertEqual(row['power_state'], 'on')
        with Bmc(SUITE_17, legacy=True) as bmc:
            result = self.run_agent(bmc)
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'unsupported')
            self.assertTrue(row['legacy_ipmi_1_5'])

    def test_cipher_query_unavailable_uses_standard_suite(self):
        with Bmc(SUITE_17, cipher_query=False) as bmc:
            result = self.run_agent(bmc)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['cipher_suite'], 17)
            self.assertEqual(row['auth'], 'hmac-sha256')
            self.assertEqual(row['device_id'], 0x20)
            self.assertNotIn('legacy_ipmi_1_5', row)
        with Bmc(SUITE_3, cipher_query=False) as bmc:
            result = self.run_agent(bmc, '--allow-suite3')
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'confirmation_required')
            self.assertEqual(row['cipher_suite'], 3)
            self.assertNotIn('legacy_ipmi_1_5', row)
        with Bmc(SUITE_3, cipher_query=False) as bmc:
            result = self.run_agent(bmc, '--confirm-suite3')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['cipher_suite'], 3)
            self.assertEqual(row['auth'], 'hmac-sha1')
            self.assertEqual(row['device_id'], 0x20)
        with Bmc(SUITE_17, cipher_query=False, open_session_ignored=True) as bmc:
            result = self.run_agent(bmc)
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'timeout')
            self.assertNotIn('legacy_ipmi_1_5', row)

    def test_unknown_auth_capabilities_are_not_legacy(self):
        with Bmc(SUITE_17, cipher_query=False, auth_unknown=True) as bmc:
            result = self.run_agent(bmc)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['cipher_suite'], 17)
            self.assertNotIn('legacy_ipmi_1_5', row)

    def test_submitted_power_timeout_is_unknown_and_not_retried(self):
        with Bmc(SUITE_17) as bmc:
            bmc.ignore_power_reply = True
            result = self.run_agent(bmc, '--action', 'soft-off', '--budget-ms', '800', '--timeout-ms', '5000')
            row = json.loads(result.stdout)
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            self.assertEqual(row['command_status'], 'outcome_unknown')
            self.assertEqual(row['close'], 'ok')
            self.assertEqual(bmc.power_requests, 1)
            self.assertEqual(bmc.power_action, 5)

    def test_rejected_close_is_not_confirmed_cleanup(self):
        for completion in (0x81, 0x87, 0xd4):
            with self.subTest(completion=completion), Bmc(SUITE_17) as bmc:
                bmc.close_completion = completion
                result = self.run_agent(bmc)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertEqual(json.loads(result.stdout)['close'], 'outcome_unknown')

    def test_cleanup_failure_returns_failure(self):
        with Bmc(SUITE_17) as bmc:
            bmc.ignore_close = True
            result = self.run_agent(bmc)
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['close'], 'timeout')

    def test_startup_budget_bounds_retries(self):
        with Bmc(SUITE_17, open_session_ignored=True) as bmc:
            started = time.monotonic()
            result = self.run_agent(bmc, '--timeout-ms', '2000', '--retries', '5', '--budget-ms', '150')
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)['status'], 'timeout')
            self.assertLess(time.monotonic() - started, 1.5)

    def test_wrong_password_fails_authentication(self):
        with Bmc(SUITE_17) as bmc:
            environment = dict(os.environ, BC_BMC_USERNAME=USERNAME, BC_BMC_PASSWORD='wrong-password')
            result = subprocess.run([AGENT, 'ipmi', '--host', '127.0.0.1', '--port', str(bmc.port),
                                     '--timeout-ms', '300', '--retries', '1'],
                                    env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)['status'], 'authentication_failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
