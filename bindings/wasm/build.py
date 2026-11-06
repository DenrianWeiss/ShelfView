#!/usr/bin/env python3
"""Build the browser decoder without transports, management, or input exports."""
import argparse
from pathlib import Path
import subprocess
import shutil

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--emcc', default='emcc')
parser.add_argument('--output', type=Path, default=root / 'frontends/web/generated')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
subprocess.run([
    args.emcc, str(root / 'bindings/wasm/decoder.c'),
    str(root / 'core/kvm.c'), str(root / 'core/display.c'),
    '-I' + str(root / 'include'), '-DBC_LOG_COMPILE_LEVEL=0', '-DBC_KVM_DECODE_ONLY=1',
    '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
    '-sMODULARIZE=1', '-sEXPORT_ES6=1', '-sALLOW_MEMORY_GROWTH=1',
    '-sMAXIMUM_MEMORY=268435456', '-sFILESYSTEM=0',
    '-sEXPORTED_FUNCTIONS=["_malloc","_free"]',
    '-sEXPORTED_RUNTIME_METHODS=["HEAPU8","HEAPU32"]',
    '-o', str(args.output / 'bcontrol-decoder.mjs'),
], check=True)
shutil.copyfile(root / 'bindings/wasm/decoder.mjs', args.output / 'console-decoder.mjs')
