#!/usr/bin/env python3
import argparse
import base64
from collections import deque
from functools import lru_cache
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
from select import select
import signal
from socketserver import BaseRequestHandler, UDPServer
import ssl
import struct
import subprocess
import tempfile
import threading
from time import monotonic
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = '/redfish/v1'
SYSTEMS = ROOT + '/Systems'
SYSTEM = SYSTEMS + '/1'
MANAGERS = ROOT + '/Managers'
MANAGER = MANAGERS + '/1'
KVM = MANAGER + '/KvmService'
MEDIA = MANAGER + '/VirtualMedia'
CD = MEDIA + '/CD'
INSERT = CD + '/Actions/VirtualMedia.InsertMedia'
EJECT = CD + '/Actions/VirtualMedia.EjectMedia'
CHASSIS = ROOT + '/Chassis'
ENCLOSURE = CHASSIS + '/1'
SENSORS = ENCLOSURE + '/Sensors'
SENSOR = SENSORS + '/CPU'
CONTROL = '/fakebmc/state'
CREDENTIALS = 'admin:test-password'
TOKEN = 'fake-kvm-token'



# Shared loopback test identity. The private key is part of this test fixture.
TEST_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIC6DCCAdCgAwIBAgIURVuiugU0xlvZZT5W4AYQ5Zg7NOYwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTExNDA5MDIzMloXDTI3MTEx
NDA5MDIzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4KH2t1yAIe3s9Y7HEF8T0dzRUJXnfVQvJRkg+H9P1xj9
Pyw5OasZ7zDNRaXXQYddhd+28Tvwq1qXb2DPnn1/fXFzxaa56fvZqMCDgg6tXHv1
sPGtqhz24m1tzFQhzMBSfUN1zDJ0YQTUTxQ52UMdBzGfB+LJTwX0/gKOLE7Rmz10
ozUF2FM2d/bbVMFItGH7Ul+XcBch2UwC5D52s9nNwlsTay67lJkcUSxAWOg3vE7o
tNRf7xGGrsAYxC1xQXlisDp/GthFCePenkbfz0uDe9/zh9VDoAw1RByEuviIJeO6
G1j1olfEOuVpD7MGBzCKtNX4wScvDKXZoTi8ofnkkQIDAQABozIwMDAdBgNVHQ4E
FgQUPiVyJlZ+gsBPasJIvQipa0WSu+swDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOCAQEACQP6uSjpsmou31TSzhG81YXrKKHPTHFB0o4VRVHTYpWIOyqb
v76xT/8f5mNqd+yuxZSTQk2PvvDWqnYIF5zgpc8Vgop01PePEcDML1KmQ5+bZt2Z
Ysc5xDHvmOInKMRYhrmRZs9dXXXj2DueNYNJXfs9ptcyYERykr+vOh5+z8Rq1Y0o
UYgUWBTOrO2jfFaRrFOnSTWEBwIa1K4d1Q/4UPvnlpoInQ770i8nckxo6wpA4DMt
yTero8evnyTEUHNiucFzEWnw2l7j5M6IF2tB59W6KJ95HWiKU+tZPgtvYVdYO7cs
qp3ZlPoN3JIgjXi/KOJB6TkEdnZjoFBi45QaXw==
-----END CERTIFICATE-----
"""

TEST_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDgofa3XIAh7ez1
jscQXxPR3NFQled9VC8lGSD4f0/XGP0/LDk5qxnvMM1FpddBh12F37bxO/CrWpdv
YM+efX99cXPFprnp+9mowIOCDq1ce/Ww8a2qHPbibW3MVCHMwFJ9Q3XMMnRhBNRP
FDnZQx0HMZ8H4slPBfT+Ao4sTtGbPXSjNQXYUzZ39ttUwUi0YftSX5dwFyHZTALk
Pnaz2c3CWxNrLruUmRxRLEBY6De8Tui01F/vEYauwBjELXFBeWKwOn8a2EUJ496e
Rt/PS4N73/OH1UOgDDVEHIS6+Igl47obWPWiV8Q65WkPswYHMIq01fjBJy8Mpdmh
OLyh+eSRAgMBAAECggEAbLiHSCz5iTJ2T01Y9IgH+Dlnh5jeLy8ZGFwGtK8tzd42
6CX31n0FMtsMZwrC2eDx93MVQMGxlMXmaI5TPpLgKy9HiODOt7xhFweCPubqqkoG
2qrGUoDtTx8GlvAbYdWttxn5ACllYXWsak/QReLxQEOYhIETzO8FqhFDjZdiZL8c
LMB8uy3gFMsIpcnZnZ/L5xRLaZugvbYCBnB1W6QkrVqfdCwx0IKF840x6Ew0kG3D
edf1YSQ2kKo5yqMilB7fFS7wstasWkQzdwASzaJkkLxzxu9NLYfszBgN8I5NCmYM
TG27BpFvS6rlQ/YsOZrACrBDrTnqHBXpOVUaTBqixwKBgQD1cJSclIq8cb3opZQA
LCcRIJ7K0VAhYYLf74ilbsK9oUwh0upTKudT7QNDhwK0QPxS6gtFurNnLChxSlVK
C+Y76uw/ITqaysaSuD0fZvT1pYqcbp4vRGKRgexdNzF3aJNwy5IGAXKG1T49WhhD
YMH/HyBwHS6hG6AKZ+Ri3GJL4wKBgQDqTDOU1E4aFPugf04m91QkzRKxdoQf9ARD
1BahuGSNO9jHSiMdu4yc/4+l1V69yKEuzv2udIytcXfMoG9pz6AkyfZZLHh+YOTk
Z+JLmRZ9q6Wk34ZbiAGsN27aBtICL7QfujCL0K/L5LFs12nTb16OUTbaNiv2X3Zt
GATWLkMf+wKBgQC/YjUPz6hK/ypFoe9BHyyrZ1NK9WJVVTL3KVHVJgQGWCMEcPG1
Pkw5niQgYMOUCOR4RvXZPpcsCTvT81GENrkl2a60H1YSY7HpsG5A8Uhrz9TA3GTO
mLV/nt7PZP1Wjh4CI0rPEgva5abtsjYfO/Cp3fyuT6MPj3oBAzgMeqrPXwKBgQDA
Ztcs7rM8Y+LGyAQrp4tntSgWp1aUztP5x17Waw/Xkz/PWChCMFOmUY9rBS8J9om2
YLCd5IPponZYiZ80axX9YAR28jf4wCT3FAAXSJ3ZkW0zWYOCAsws2lCjplorBXWL
YGChUDws2Z6B3NvAj4I8qKC8zSOI7JfZupGuOMtSpQKBgE+Ljo1fmR8RfkF1fw+D
1gv08u3Sk/AmF+FErE2eYEf8CWKfxxXONof+r4ZyoFG8VyZW7u5vgJCBPDwmwMiY
DLHTC56G5XZY3/lHcKnl8e1xYg79GIHprr1WRZ1pI0npiwHMLdlPm4sbdpzmK7FQ
L6VQmN63Gh2qUIObVWHmI0Z9
-----END PRIVATE KEY-----
"""

WIDTH, HEIGHT = 640, 360
UNSHIFTED = '1234567890-=[]\\#;\'\x60,./'
SHIFTED = '!@#$%^&*()_+{}|~:"~<>?'


def typed_text(text, old_keys, report):
    shifted = bool(report[0] & 0x22)
    keys = set(report[2:]) - {0}
    for key in dict.fromkeys(report[2:]):
        if key not in keys - old_keys:
            continue
        if 4 <= key <= 29:
            text += chr((65 if shifted else 97) + key - 4)
        elif 30 <= key <= 39:
            text += (SHIFTED if shifted else UNSHIFTED)[key - 30]
        elif 45 <= key <= 56:
            text += (SHIFTED if shifted else UNSHIFTED)[key - 35]
        elif key == 42:
            text = text[:-1]
        else:
            text += {40: '\n', 43: '    ', 44: ' '}.get(key, '')
    return text[-512:], keys


@lru_cache(maxsize=1)
def screen_font():
    from PIL import ImageFont
    return ImageFont.load_default(size=13)


def pixels(state):
    from PIL import Image, ImageDraw

    font = screen_font()
    temperature, media, mouse, buttons, text = state
    image = Image.new('1', (WIDTH // 2, HEIGHT // 2))
    draw = ImageDraw.Draw(image)
    draw.text((12, 8), 'Fake BMC  /  KVM test', fill=1, font=font)
    draw.line((12, 28, 308, 28), fill=1)
    draw.text((12, 33), f'CPU {temperature} C   Mouse {mouse[0]},{mouse[1]}   Buttons {buttons}', fill=1, font=font)
    media_label = 'Ejected'
    if media:
        name = unquote(media.partition('?')[0].rstrip('/').rsplit('/', 1)[-1])
        media_label = 'Mounted: ' + ''.join(c if c.isprintable() else ' ' for c in name[:30])
    draw.text((12, 54), f'Remote media: {media_label}', fill=1, font=font)
    draw.text((12, 76), 'Keyboard input', fill=1, font=font)
    draw.rectangle((12, 97, 307, 169), outline=1)
    lines = []
    for line in text.split('\n'):
        lines.extend(line[index:index + 24] for index in range(0, max(1, len(line)), 24))
    draw.multiline_text((18, 103), '\n'.join(lines[-3:]), fill=1, font=font)
    x, y = mouse[0] // 2, mouse[1] // 2
    draw.polygon([(x, y), (x, y + 12), (x + 3, y + 9), (x + 6, y + 14),
                  (x + 8, y + 13), (x + 5, y + 8), (x + 10, y + 8)], fill=1, outline=0)
    return image.resize((WIDTH, HEIGHT), Image.Resampling.NEAREST).tobytes()


def video(state):
    bitmap = pixels(state)
    stride = WIDTH // 8
    blocks = []
    for y in range(0, HEIGHT, 8):
        for x in range(stride):
            tile = bitmap[y * stride + x:(y + 8) * stride + x:stride]
            if tile == bytes(8):
                blocks.append('0101000')  # Solid palette index 0.
            elif tile == b'\xff' * 8:
                blocks.append('0101001')  # Solid palette index 1.
            else:
                blocks.append('0110000001' + f'{int.from_bytes(tile, "big"):064b}')
    bits = ''.join(blocks) + '1001'  # End of frame.
    bits += '0' * ((-len(bits) % 32) + 64)
    payload = b''.join(struct.pack('<I', int(bits[i:i + 32], 2)) for i in range(0, len(bits), 32))
    header = bytearray(86)
    struct.pack_into('<HH', header, 4, WIDTH, HEIGHT)
    struct.pack_into('<HH', header, 13, WIDTH, HEIGHT)
    struct.pack_into('<I', header, 26, 1)
    struct.pack_into('<I', header, 69, len(payload))
    return bytes(2) + header + payload


SUITE_17 = bytes([0xc0, 0x11, 0x03, 0x04, 0x01])
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


class RmcpProtocol:
    def __init__(self, records, password):
        self.records = records
        self.suites = []
        remaining = records
        while len(remaining) >= 5 and remaining[0] == 0xc0:
            self.suites.append((remaining[2] & 0x3f, remaining[3] & 0x3f, remaining[4] & 0x3f))
            remaining = remaining[5:]
        self.key = password.encode().ljust(20, b'\0')
        self.out_sequence = 1
        self.closed = False
        self.in_sequence = 0
        self.boot_flags = bytes(5)
        self.boot_progress = 0
        self.sel_reservation = 0

    def handle(self, datagram):
        assert datagram[0:4] == b'\x06\x00\xff\x07', datagram.hex()
        if datagram[4] == 0x00:
            length = datagram[13]
            _, netfn, _, _, sequence, command, data = parse_message(datagram[14:14 + length])
            if netfn != 0x06 or command != 0x38:
                return None
            channel = data[0] & 0x0f
            capabilities = bytes([channel, 0x84, 0x04, 0x03, 0, 0, 0, 0])
            message = build_message(0x07, command, capabilities, sequence)
            return bytes([0x06, 0x00, 0xff, 0x07, 0x00]) + bytes(8) + bytes([len(message)]) + message
        auth, payload_type = datagram[4], datagram[5] & 0x3f
        session_id = int.from_bytes(datagram[6:10], 'little')
        assert auth == 0x06
        length = int.from_bytes(datagram[14:16], 'little')
        payload = datagram[16:16 + length]
        if payload_type == 0x00 and session_id == 0:
            return self.sessionless(payload)
        if payload_type == 0x10:
            return self.open_session(payload)
        if payload_type == 0x12:
            return self.rakp1(payload)
        if payload_type == 0x14:
            return self.rakp3(payload)
        if session_id == self.bmc_id:
            if payload_type == 0:
                return self.command(datagram, payload)
            if payload_type == 1 and self.sol_active:
                return self.sol_input(self.unwrap(datagram, payload))
        raise AssertionError(f'unexpected payload {payload_type:#x}')

    def sessionless(self, payload):
        _, netfn, _, _, sequence, command, data = parse_message(payload)
        assert netfn == 0x06 and command == 0x54 and sequence < 64
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
        role = self.requested_role = payload[24]
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
        role, length = self.requested_role, len(self.username)
        expected = digest(self.key, self.bmc_random + self.console_id.to_bytes(4, 'little') +
                          bytes([role, length]) + self.username, self.algorithm)
        if not hmac.compare_digest(payload[8:], expected):
            raise ValueError('RAKP3 auth code mismatch')
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

    def temperature(self):
        return 25

    def unwrap(self, datagram, payload):
        incoming_sequence = int.from_bytes(datagram[10:14], 'little')
        assert (incoming_sequence == 1 if not self.in_sequence else incoming_sequence > self.in_sequence), 'session sequence must start at one and reject replay'
        length = int.from_bytes(datagram[14:16], 'little')
        if self.integrity_algorithm != 0:
            integrity_size = 12 if self.integrity_algorithm == 1 else 16
            pad = (4 - ((12 + length + 2) % 4)) % 4
            trailer = datagram[16 + length:16 + length + pad + 2]
            assert trailer[:pad] == b'\xff' * pad and trailer[pad] == pad and trailer[pad + 1] == 0x07
            expected = digest(self.k1, datagram[4:16 + length + pad + 2], self.algorithm)[:integrity_size]
            if not hmac.compare_digest(datagram[16 + length + pad + 2:], expected):
                raise ValueError('session integrity mismatch')
        if datagram[5] & 0xc0 != 0xc0:
            raise ValueError('SOL and IPMI require authenticated encryption framing')
        ciphertext = payload[16:]
        plain = aes_cbc(self.k2[:16], payload[:16], ciphertext, decrypt=True)
        pad = plain[-1]
        plain = plain[:-pad - 1] if pad else plain[:-1]
        self.in_sequence = incoming_sequence
        return plain

    def command(self, datagram, payload):
        _, netfn, _, _, sequence, command, data = parse_message(self.unwrap(datagram, payload))
        completion, response_data = self.command_response(netfn, command, data)
        return self.wrap(build_message(netfn + 1, command, response_data, sequence, completion))

    def wrap(self, message, kind=0):
        pad = 16 - ((len(message) + 1) % 16)
        if pad == 16:
            pad = 0
        padded = message + bytes(range(1, pad + 1)) + bytes([pad])
        iv = os.urandom(16)
        encrypted = iv + aes_cbc(self.k2[:16], iv, padded)
        header = bytearray(12)
        header[0] = 0x06
        header[1] = kind | 0x80 | (0x40 if self.integrity_algorithm else 0)
        header[2:6] = self.console_id.to_bytes(4, 'little')
        header[6:10] = self.out_sequence.to_bytes(4, 'little')
        self.out_sequence = (self.out_sequence + 1) & 0xffffffff or 1
        header[10:12] = len(encrypted).to_bytes(2, 'little')
        integrity_pad = (4 - ((12 + len(encrypted) + 2) % 4)) % 4
        trailer = b'\xff' * integrity_pad + bytes([integrity_pad, 0x07])
        body = bytes(header) + encrypted + trailer
        auth = digest(self.k1, body, self.algorithm)[:12 if self.integrity_algorithm == 1 else 16]
        return b'\x06\x00\xff\x07' + body + auth


    def command_response(self, netfn, command, data):
        operation = netfn, command
        if operation == (0x06, 0x3b):
            return 0, bytes([self.privilege])
        if operation == (0x06, 0x01):
            return 0, DEVICE_ID
        if operation == (0x06, 0x3c):
            if int.from_bytes(data, 'little') != self.bmc_id:
                return 0x87, b''
            self.closed = True
            return 0, b''
        if operation == (0x00, 0x01):
            return 0, bytes([1, 0, 0, 0])
        if operation == (0x00, 0x02):
            return 0, b''
        if operation == (0x00, 0x09):
            if data not in (bytes(3), bytes([5, 0, 0])):
                return 0xcc, b''
            flags = bytes([self.boot_progress]) if data[0] == 0 else self.boot_flags
            return 0, bytes([1, data[0]]) + flags
        if operation == (0x00, 0x08):
            if len(data) == 2 and data[0] == 0:
                self.boot_progress = data[1]
            elif len(data) == 6 and data[0] == 5 and self.boot_progress == 1:
                self.boot_flags = data[1:]
            else:
                return 0xcc, b''
            return 0, b''
        if operation == (0x0a, 0x20):
            return 0, bytes([0x51, 1]) + bytes(11)
        if operation == (0x0a, 0x22):
            return 0, b'\x34\x12'
        if operation == (0x0a, 0x23):
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
            return 0, b'\xff\xff' + bytes(record)
        if operation == (0x04, 0x2d):
            return (0, bytes([self.temperature(), 0xc0])) if data == b'\x23' else (0xcb, b'')
        if operation == (0x0a, 0x40):
            return 0, b'\x51\x00\x00\x00\x10\x04\x03\x02\x01' + bytes(4) + b'\x40'
        if operation == (0x0a, 0x42):
            self.sel_reservation = self.sel_reservation % 65535 + 1
            return 0, self.sel_reservation.to_bytes(2, 'little')
        if operation == (0x0a, 0x43):
            return (0xca if int.from_bytes(data[:2], 'little') == self.sel_reservation else 0xc5), b''
        if operation == (0x0a, 0x10):
            return 0xc7, b''
        if operation == (0x0a, 0x11):
            return 0xc9, b''
        if operation == (0x06, 0x42):
            return 0xcc, b''
        if operation == (0x0c, 0x02):
            return 0x80, b''
        return 0xc1, b''


class Peer(RmcpProtocol):
    def __init__(self, state, username, password, server):
        super().__init__(SUITE_17, password)
        self.username = username.encode()
        self.state = state
        self.server = server
        self.sol_active = False
        self.sol_output = bytearray()
        self.sol_pending = b''
        self.sol_received = None
        self.sol_sequence = 0

    def command_response(self, netfn, command, data):
        operation = netfn, command
        if operation == (6, 0x4e):
            return 0, b'\x03' + bytes(7)
        if operation == (6, 0x4f):
            return 0, b'\x10'
        if operation == (12, 0x22):
            config = {0: b'\0', 1: b'\x01', 2: b'\xc2', 5: b'\x07', 6: b'\x07',
                      7: b'\x01', 8: self.server.server_address[1].to_bytes(2, 'little')}
            value = config.get(data[1])
            return (0, b'\x11' + value) if value is not None else (0x80, b'')
        if operation == (6, 0x4a):
            return 0, bytes([1, int(self.server.sol_owner is not None), 0])
        if operation == (6, 0x4b):
            owner = self.server.sol_owner
            return 0, (owner.bmc_id if owner else 0).to_bytes(4, 'little') + bytes(8)
        if operation == (6, 0x48):
            if len(data) != 6 or data[:2] != b'\x01\x01':
                return 0xcc, b''
            if self.server.sol_owner is not None:
                return 0x80, b''
            self.server.sol_owner = self
            self.sol_active = True
            self.sol_output.extend(b'Fake BMC SOL\r\nType to test serial echo.\r\n> ')
            return 0, bytes(4) + struct.pack('<HHHH', 259, 259, self.server.server_address[1], 0xffff)
        if operation == (6, 0x49):
            if not self.sol_active:
                return 0x80, b''
            self.close_sol()
            return 0, b''
        return super().command_response(netfn, command, data)

    def close_sol(self):
        if self.server.sol_owner is self:
            self.server.sol_owner = None
        self.sol_active = False
        self.sol_output.clear()
        self.sol_pending = b''
        self.sol_received = None

    def sol_input(self, packet):
        sequence, ack, count, flags = packet[:4]
        data = packet[4:]
        if sequence > 15 or len(data) > 255:
            return None
        if self.sol_pending and ack == self.sol_sequence and not flags & 0x40:
            if count <= len(self.sol_pending):
                self.sol_output[:0] = self.sol_pending[count:]
                self.sol_pending = b''
        accepted = 0
        if sequence:
            if self.sol_received != (sequence, data):
                self.sol_received = sequence, data
                self.sol_output.extend(data.replace(b'\r', b'\r\n> '))
                del self.sol_output[4096:]
            accepted = len(data)
        if sequence:
            return self.wrap(bytes([0, sequence, accepted, 0]), 1)
        return None

    def sol_packet(self):
        if not self.sol_active or self.sol_pending or not self.sol_output:
            return None
        self.sol_sequence = self.sol_sequence % 15 + 1
        self.sol_pending = bytes(self.sol_output[:255])
        del self.sol_output[:255]
        return self.wrap(bytes([self.sol_sequence, 0, 0, 0]) + self.sol_pending, 1)

    def temperature(self):
        with self.state.lock:
            return self.state.temperature

    def rakp1(self, payload):
        if (len(payload) < 28 or payload[28:] != self.username or payload[27] != len(self.username)
                or int.from_bytes(payload[4:8], 'little') != self.bmc_id):
            return None
        return super().rakp1(payload)

    def rakp3(self, payload):
        if len(payload) < 8 or int.from_bytes(payload[4:8], 'little') != self.bmc_id:
            return None
        return super().rakp3(payload)


class Request(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        if len(data) < 14 or not data.startswith(b'\x06\x00\xff\x07'):
            return
        now = monotonic()
        peers = self.server.peers
        for address, (last_seen, expired) in list(peers.items()):
            if now - last_seen > 300:
                expired.close_sol()
                del peers[address]
        opening = data[4] == 6 and data[5] == 0x10
        entry = peers.get(self.client_address)
        if opening or entry is None:
            if entry is None and len(peers) >= 64:
                return
            peer = Peer(self.server.state, *self.server.credentials, self.server)
        else:
            peer = entry[1]
        try:
            response = peer.handle(data)
        except (AssertionError, AttributeError, IndexError, KeyError, ValueError, subprocess.CalledProcessError):
            return
        if response:
            if peer.closed:
                peer.close_sol()
                peers.pop(self.client_address, None)
            elif hasattr(peer, 'bmc_id'):
                if entry is not None and entry[1] is not peer:
                    entry[1].close_sol()
                peers[self.client_address] = (now, peer)
            socket.sendto(response, self.client_address)
        if peer.sol_active:
            peers[self.client_address] = (now, peer)
            output = peer.sol_packet()
            if output:
                socket.sendto(output, self.client_address)


class RmcpServer(UDPServer):
    def __init__(self, address, state, credentials):
        super().__init__(address, Request)
        self.state = state
        self.credentials = credentials
        self.peers = {}
        self.sol_owner = None


def link(path):
    return {'@odata.id': path}


def collection(path, kind):
    name = kind + 'Collection'
    return {'@odata.type': f'#{name}.{name}', 'Members': [link(path)], 'Members@odata.count': 1}


def websocket_frames(connection):
    buffer = bytearray()
    while True:
        if not connection.pending() and not select([connection], [], [], 0.1)[0]:
            yield None
            continue
        chunk = connection.recv(65536)
        if not chunk:
            return
        buffer.extend(chunk)
        while len(buffer) >= 2:
            flags, length = buffer[0], buffer[1] & 127
            if flags & 0xf0 != 0x80 or not buffer[1] & 128 or length == 127:
                return
            offset = 2
            if length == 126:
                if len(buffer) < 4:
                    break
                length = int.from_bytes(buffer[2:4], 'big')
                offset = 4
            end = offset + 4 + length
            if len(buffer) < end:
                break
            mask = buffer[offset:offset + 4]
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(buffer[offset + 4:end]))
            del buffer[:end]
            yield flags & 15, payload


class State:
    def __init__(self, temperature):
        self.temperature = temperature
        self.image = None
        self.inputs = deque(maxlen=100)
        self.mouse = (WIDTH // 2, HEIGHT // 2)
        self.buttons = 0
        self.text = ''
        self.lock = threading.Lock()

    def screen(self):
        with self.lock:
            return self.temperature, self.image, self.mouse, self.buttons, self.text

    def input(self, payload, previous_keys):
        device, report = payload[17], payload[33:]
        with self.lock:
            if device == 48 and len(report) == 8:
                self.text, previous_keys = typed_text(self.text, previous_keys, report)
                self.inputs.append({'device': 'keyboard', 'report': report.hex()})
            elif device == 49 and len(report) == 6:
                self.buttons, x, y, _ = struct.unpack('<BHHb', report)
                self.mouse = (round(min(x, 32767) * (WIDTH - 1) / 32767),
                              round(min(y, 32767) * (HEIGHT - 1) / 32767))
                self.inputs.append({'device': 'mouse', 'report': report.hex()})
        return previous_keys


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def reply(self, status, body=None, headers=()):
        data = b'' if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Type', 'application/json')
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        expected = 'Basic ' + base64.b64encode(CREDENTIALS.encode()).decode()
        if self.headers.get('Authorization') == expected:
            return True
        self.reply(401, {}, [('WWW-Authenticate', 'Basic realm="Fake BMC"')])
        return False

    def body(self):
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 <= size <= 65536:
            self.close_connection = True
            raise ValueError('Invalid body length')
        return self.rfile.read(size)

    def do_GET(self):
        path = urlsplit(self.path).path.rstrip('/')
        if path == '/kvm':
            self.console()
            return
        if path in ('/api/settings/media/remote/h5kvm_enable_flag', '/viewer.min.js'):
            self.reply(404, {})
            return
        if path != ROOT and path != '/api/settings/media/h5viewercfg' and not self.authorized():
            return
        if path == KVM:
            authority = self.headers.get('Host', '')
            if not re.fullmatch(r'(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?', authority):
                self.reply(400, {'error': 'Invalid Host header'})
                return
            self.reply(200, {**link(KVM), '@odata.type': '#KvmService.v1_0_0.KvmService',
                             'KvmUrl': f'https://{authority}/viewer.html?&token=fake-launch-token'})
            return
        state = self.server.state
        with state.lock:
            temperature, image, inputs = state.temperature, state.image, list(state.inputs)
        resources = {
            ROOT: {'@odata.type': '#ServiceRoot.v1_17_0.ServiceRoot', 'RedfishVersion': '1.17.0', 'Product': 'ZTE Redfish Server',
                   'Systems': link(SYSTEMS), 'Managers': link(MANAGERS), 'Chassis': link(CHASSIS)},
            SYSTEMS: collection(SYSTEM, 'ComputerSystem'),
            SYSTEM: {'@odata.type': '#ComputerSystem.v1_22_0.ComputerSystem', 'Id': '1', 'Name': 'Fake BMC host',
                     'Manufacturer': 'Fake BMC', 'Model': 'KVM test host', 'PowerState': 'On',
                     'Links': {'Chassis': [link(ENCLOSURE)], 'ManagedBy': [link(MANAGER)]}},
            MANAGERS: collection(MANAGER, 'Manager'),
            MANAGER: {'@odata.type': '#Manager.v1_15_0.Manager', 'Id': '1', 'Name': 'Fake BMC', 'KvmService': link(KVM), 'VirtualMedia': link(MEDIA),
                      'GraphicalConsole': {'ServiceEnabled': True, 'Port': self.server.server_port,
                                           'ConnectTypesSupported': ['KVMIP']},
                      'Actions': {'Oem': {'#Manager.Dump': {'target': MANAGER + '/Actions/Oem/ZTE/Manager.Dump'}}}},
            MEDIA: collection(CD, 'VirtualMedia'),
            CD: {'@odata.type': '#VirtualMedia.v1_7_0.VirtualMedia', 'Id': 'CD', 'Name': 'Virtual CD',
                 'MediaTypes': ['CD', 'DVD'], 'Inserted': image is not None, 'Image': image,
                 'WriteProtected': True, 'ConnectedVia': 'URI' if image else 'NotConnected',
                 'Actions': {'#VirtualMedia.InsertMedia': {'target': INSERT},
                             '#VirtualMedia.EjectMedia': {'target': EJECT}}},
            CHASSIS: collection(ENCLOSURE, 'Chassis'),
            ENCLOSURE: {'@odata.type': '#Chassis.v1_22_0.Chassis', 'Id': '1', 'Name': 'Fake chassis', 'Sensors': link(SENSORS)},
            SENSORS: collection(SENSOR, 'Sensor'),
            SENSOR: {'@odata.type': '#Sensor.v1_11_1.Sensor', 'Id': 'CPU', 'Name': 'CPU Temperature',
                     'Reading': temperature, 'ReadingType': 'Temperature', 'ReadingUnits': 'Cel', 'PhysicalContext': 'CPU',
                     'Status': {'State': 'Enabled', 'Health': 'OK'}},
            CONTROL: {'temperature': temperature, 'image': image, 'inputs': inputs},
        }
        if path == '/api/settings/media/h5viewercfg':
            if self.session():
                self.reply(200, {'token': TOKEN, 'session': 'fake', 'client_ip': self.client_address[0],
                                 'server_ip': self.server.server_address[0]})
            else:
                self.reply(401, {})
        elif path in resources:
            self.reply(200, {**link(path), **resources[path]})
        else:
            self.reply(404, {})

    def session(self):
        return ('QSESSIONID=fake-session' in self.headers.get('Cookie', '').split('; ')
                and self.headers.get('X-CSRFTOKEN') == 'fake-csrf')

    def do_POST(self):
        try:
            raw = self.body()
            if self.path == '/api/session':
                form = parse_qs(raw.decode())
                if form == {'cmccflag': ['true'], 'cmcctoken': ['fake-launch-token'], 'kvmflag': ['true']}:
                    self.reply(200, {'CSRFToken': 'fake-csrf'},
                               [('Set-Cookie', 'QSESSIONID=fake-session; Path=/; HttpOnly; Secure')])
                else:
                    self.reply(401, {})
                return
            if not self.authorized():
                return
            body = json.loads(raw or b'{}')
            if not isinstance(body, dict):
                raise ValueError('Expected a JSON object')
            state = self.server.state
            with state.lock:
                if self.path == INSERT:
                    image = body.get('Image')
                    if not isinstance(image, str) or not image.strip():
                        raise ValueError('Image must be a nonempty URI')
                    state.image = image
                elif self.path == EJECT:
                    state.image = None
                elif self.path == CONTROL:
                    temperature = body.get('temperature')
                    if type(temperature) is not int or not 0 <= temperature <= 255:
                        raise ValueError('temperature must be an integer from 0 to 255')
                    state.temperature = temperature
                else:
                    self.reply(404, {})
                    return
            self.reply(204)
        except ValueError as error:
            self.reply(400, {'error': str(error)})

    def do_DELETE(self):
        self.body()
        self.reply(204 if self.path.startswith('/api/session') else 404)

    def send_frame(self, opcode, data):
        length = len(data)
        if length < 126:
            header = bytes([length])
        elif length < 65536:
            header = b'\x7e' + struct.pack('!H', length)
        else:
            header = b'\x7f' + struct.pack('!Q', length)
        self.wfile.write(bytes([0x80 | opcode]) + header + data)

    def console(self):
        key = self.headers.get('Sec-WebSocket-Key')
        if self.headers.get('Upgrade', '').lower() != 'websocket' or not key:
            self.reply(400, {})
            return
        offered = self.headers.get('Sec-WebSocket-Protocol', '').replace(' ', '').split(',')
        binary = 'binary' in offered
        protocol = 'binary' if binary else 'base64'
        accept = hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', base64.b64encode(accept).decode())
        if protocol in offered:
            self.send_header('Sec-WebSocket-Protocol', protocol)
        self.end_headers()
        self.close_connection = True

        def send(kind, data, status=0):
            packet = struct.pack('<HIH', kind, len(data), status) + data
            self.send_frame(2, packet) if binary else self.send_frame(1, base64.b64encode(packet))

        self.connection.settimeout(5)
        try:
            send(23, b'', 2)
            authenticated = False
            deadline = monotonic() + 5
            next_frame = 0
            previous_screen = None
            previous_keys = set()
            state = self.server.state
            for frame in websocket_frames(self.connection):
                now = monotonic()
                if authenticated and now >= next_frame:
                    screen = state.screen()
                    if screen != previous_screen:
                        send(25, video(screen))
                        previous_screen = screen
                    next_frame = now + 0.05
                elif not authenticated and now >= deadline:
                    return
                if frame is None:
                    continue
                opcode, data = frame
                if opcode == 8:
                    self.send_frame(8, data)
                    return
                if opcode == 9:
                    self.send_frame(10, data)
                    continue
                if opcode not in (1, 2):
                    continue
                if opcode == 1:
                    data = base64.b64decode(data, validate=True)
                while len(data) >= 8:
                    kind, size, _ = struct.unpack_from('<HIH', data)
                    if size > len(data) - 8:
                        return
                    payload, data = data[8:8 + size], data[8 + size:]
                    if not authenticated and kind == 18:
                        authenticated = payload[1:].split(b'\0', 1)[0] == TOKEN.encode()
                        send(19, bytes([authenticated]))
                        if not authenticated:
                            return
                        previous_screen = state.screen()
                        send(25, video(previous_screen))
                        next_frame = now + 0.05
                    elif authenticated and kind == 1 and size >= 39:
                        previous_keys = state.input(payload, previous_keys)
        except (OSError, ValueError, struct.error):
            return


def stop(_signal, _frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, stop)
    parser = argparse.ArgumentParser(description='Fake BMC for bControl')
    parser.add_argument('--bind', type=IPv4Address, default=IPv4Address('127.0.0.1'),
                        help='IPv4 address for HTTPS and RMCP+')
    parser.add_argument('--port', type=int, default=8443, help='HTTPS port')
    parser.add_argument('--rmcp-port', type=int, default=623, help='RMCP+ UDP port')
    parser.add_argument('--temperature', type=int, choices=range(256), default=25, metavar='0..255')
    parser.add_argument('--cert', type=Path)
    parser.add_argument('--key', type=Path)
    parser.add_argument('--export-ca', type=Path, help='export the built-in test certificate and exit')
    args = parser.parse_args()
    if args.export_ca:
        with args.export_ca.open('x', encoding='ascii') as output:
            output.write(TEST_CERTIFICATE)
        return
    try:
        screen_font()
    except ImportError:
        parser.error('KVM requires Pillow. Install it with python -m pip install Pillow')
    if bool(args.cert) != bool(args.key):
        parser.error('--cert and --key must be supplied together')
    if args.bind.is_unspecified:
        parser.error('--bind requires a concrete IPv4 address for the KVM URL')
    if str(args.bind) != '127.0.0.1' and not args.cert:
        parser.error('A non-default bind address requires --cert and --key for that IP')
    host = str(args.bind)
    with tempfile.TemporaryDirectory(prefix='fakebmc-') as directory:
        cert, key = args.cert, args.key
        if cert is None:
            cert, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            cert.write_text(TEST_CERTIFICATE, encoding='ascii')
            with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='ascii') as output:
                output.write(TEST_PRIVATE_KEY)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        state = State(args.temperature)
        with (ThreadingHTTPServer((host, args.port), Handler) as server,
              RmcpServer((host, args.rmcp_port), state, CREDENTIALS.split(':', 1)) as rmcp):
            server.state = state
            server.origin = f'https://{host}:{server.server_port}'
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=rmcp.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
            worker.start()
            print(f'{server.origin}\nCA: {cert}\nCredentials: {CREDENTIALS}\nRMCP+: {host}:{rmcp.server_address[1]}',
                  flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                rmcp.shutdown()
                worker.join()


if __name__ == '__main__':
    main()
