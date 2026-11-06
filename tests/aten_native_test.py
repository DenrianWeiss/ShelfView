"""Exercise bounded ELF evidence parsing without executing or shipping vendor libraries."""
import ctypes
import io
import struct
import sys
import zipfile

lib = ctypes.CDLL(sys.argv[1])
for name in ('native_media_layout', 'native_jar_media_layout','native_mouse_bytes','native_mouse_cipher'):
    f = getattr(lib, 'bc_aten_' + name)
    f.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    f.restype = ctypes.c_uint32

from aten_native_fixture import fixture

def check(data, expected, jar=False):
    output = ctypes.c_uint32(123)
    buf = ctypes.create_string_buffer(bytes(data))
    result = getattr(lib, 'bc_aten_native_jar_media_layout' if jar else 'bc_aten_native_media_layout')(buf, len(data), ctypes.byref(output))
    assert (result == 0) == bool(expected), (result, expected)
    assert output.value == expected

original = fixture()
check(original, 2)
check(fixture(4), 1)
check(fixture(1), 0)
for offset in (4, 5, 18, 58, 512, 561, 608, 768, 783, 912):
    data = bytearray(original)
    data[offset] ^= 1
    check(data, 0)
for length in (0, 63, 64, 255, 512, 1100, 1248, 1271):
    check(original[:length], 0)
for offset in (40, 64+64+24, 64+192+24):
    data = bytearray(original)
    struct.pack_into('<Q', data, offset, 0xfffffffffffffff0)
    check(data, 0)
for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compression) as z:
        z.writestr('libSharedLibrary64.so', original)
    check(out.getvalue(), 2, jar=True)
print('ATEN native evidence: symbol/ISO mapping, malformed offsets and JAR extraction passed')

from aten_native_fixture import mouse_fixture
mouse=mouse_fixture()
def check_mouse(data,expected):
    out=ctypes.c_uint32(99)
    buf=ctypes.create_string_buffer(bytes(data))
    result=lib.bc_aten_native_mouse_bytes(buf,len(data),ctypes.byref(out))
    assert (result==0)==bool(expected) and out.value==expected,(result,out.value)
check_mouse(mouse,3)
for offset in (512,524,551,563,576):
    changed=bytearray(mouse);changed[offset]^=1;check_mouse(changed,0)
check_mouse(original,0)

from aten_native_fixture import mouse_cipher_fixture
cipher=mouse_cipher_fixture()
def check_cipher(data,expected):
    out=ctypes.c_uint32(99);buf=ctypes.create_string_buffer(bytes(data))
    status=lib.bc_aten_native_mouse_cipher(buf,len(data),ctypes.byref(out))
    assert (status==0)==bool(expected) and out.value==expected,(status,out.value)
check_cipher(cipher,1)
for offset in (768+4,768+0x42,1400,2100,2112):
    changed=bytearray(cipher);changed[offset]^=1;check_cipher(changed,0)
check_cipher(mouse_fixture(),0)
