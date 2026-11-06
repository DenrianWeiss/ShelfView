"""Pack200 resource extraction; fixture keys are public test-only identities."""
import ctypes
import gzip
from pathlib import Path
import sys
from concurrent.futures import ThreadPoolExecutor
lib=ctypes.CDLL(sys.argv[1])
lib.bc_aten_native_jar_media_layout.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)]
lib.bc_aten_identity_extract.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_void_p)]
lib.bc_aten_identity_destroy.argtypes=[ctypes.c_void_p]
packed=Path(__file__).with_name('fixtures').joinpath('aten/resources.pack.gz').read_bytes()
raw=gzip.decompress(packed)
def check(data, success):
    b=ctypes.create_string_buffer(data)
    layout=ctypes.c_uint32(99)
    result=lib.bc_aten_native_jar_media_layout(b,len(data),ctypes.byref(layout))
    assert (result==0)==success,(result,len(data))
    assert layout.value==(2 if success else 0)
    identity=ctypes.c_void_p()
    result=lib.bc_aten_identity_extract(b,len(data),ctypes.byref(identity))
    assert (result==0)==success
    assert bool(identity.value)==success
    lib.bc_aten_identity_destroy(identity)
for data in (raw,packed):
    check(data,True)
    for length in (1,4,8,20,len(data)//2,len(data)-1):check(data[:length],False)
check(packed+b'trailing',False)
with ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(lambda _:check(packed,True),range(12)))
print('Pack200: raw/gzip identity and native resources, truncated input and concurrent extraction passed')
