"""Synthetic AST frames compared to independent noVNC pixel results."""
import json
from pathlib import Path
import subprocess
import sys
vectors=json.loads(Path(__file__).with_name('fixtures').joinpath('aten/ast-vectors.json').read_text())
def decode(data,w=8,h=8):
    return subprocess.run([sys.argv[1],str(w),str(h)],input=data,capture_output=True,timeout=5)
for v in vectors:
    data=bytes.fromhex(v['payload']);expected=bytes.fromhex(v['rgba'])
    result=decode(data,v['w'],v['w'])
    assert result.returncode==0,(v['q'],v['mode'],result.returncode)
    assert result.stdout==expected,(v['q'],v['mode'],max(abs(a-b) for a,b in zip(result.stdout,expected)))
    assert decode(data[:8],v['w'],v['w']).returncode!=0
for header in (bytes([12,0,1,188]),bytes([0,12,1,188]),bytes([0,0,0,0])):
    assert decode(header+bytes(8)).returncode!=0
# End marker is mandatory; zero padding must not become an endless sequence of blocks.
assert decode(bytes([0,0,1,188])+bytes(32)).returncode!=0
print('ATEN AST: 24 independent pixel vectors and malformed frame rejection passed')
