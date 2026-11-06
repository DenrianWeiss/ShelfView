import ctypes
import io
import pathlib
import subprocess
import sys
import tempfile
import warnings
import zipfile

lib = ctypes.CDLL(sys.argv[1])
class String(ctypes.Structure):
    _fields_ = [('data', ctypes.c_void_p), ('length', ctypes.c_uint64)]
lib.bc_aten_identity_extract.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
lib.bc_aten_identity_extract.restype = ctypes.c_uint32
lib.bc_aten_identity_destroy.argtypes = [ctypes.c_void_p]
for name in ('certificate', 'private_key'):
    function = getattr(lib, 'bc_aten_identity_' + name)
    function.argtypes = [ctypes.c_void_p]
    function.restype = String

def archive(entries, method):
    out = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(out, 'w', compression=method) as z:
        warnings.simplefilter('ignore', UserWarning)
        for name, data in entries:
            z.writestr(name, data)
    return out.getvalue()

def extract(data, success, expected=None):
    identity = ctypes.c_void_p()
    buffer = ctypes.create_string_buffer(data)
    status = lib.bc_aten_identity_extract(buffer, len(data), ctypes.byref(identity))
    assert (status == 0) == success, status
    assert bool(identity.value) == success
    if success:
        for name, wanted in zip(('certificate', 'private_key'), expected):
            got = getattr(lib, 'bc_aten_identity_' + name)(identity)
            assert ctypes.string_at(got.data, got.length) == wanted
    lib.bc_aten_identity_destroy(identity)

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    for suffix in ('', 'other'):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / ('key' + suffix)), '-out', str(root / ('cert' + suffix)),
                        '-days', '1', '-subj', '/CN=fixture'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cert, key = (root / 'cert').read_bytes(), (root / 'key').read_bytes()
    entries = [('res/client.crt', cert), ('res/client.key', key)]
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        data = archive(entries, method)
        extract(data, True, (cert, key))
        extract(data[:-1], False)
        damaged = bytearray(data)
        damaged[50] ^= 1
        extract(bytes(damaged), False)
        extract(archive(entries[:1], method), False)
        extract(archive(entries + entries[:1], method), False)
        extract(archive([entries[0], ('res/client.key', (root / 'keyother').read_bytes())], method), False)
        extract(archive([entries[0], ('res/client.key', b'not a key')], method), False)
        extract(archive([('res/client.crt', b'x' * 65537), entries[1]], method), False)
print('ATEN identity extraction: stored/deflate, CRC, truncation, duplicates and key matching passed')
