#!/usr/bin/env python3
"""桌面端绑定测试用 RMCP+/SOL BMC 夹具。

复用 tests/ipmi_integration.py 的独立 Bmc/RMCP+ 实现（不调用产品编码器）。
用法: ipmi_bmc_fixture.py
打印 READY 与实际端口后持续服务，直到进程被终止；prints 后进入 stdin 等待，
EOF 或 SIGTERM 退出。
"""
import pathlib
import sys

FIXED_PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 0

ROOT = next(parent for parent in pathlib.Path(__file__).resolve().parents
            if (parent / 'tests' / 'ipmi_integration.py').is_file())
sys.path.insert(0, str(ROOT / 'tests'))

# ipmi_integration 模块级代码会 pop argv[1]；用占位值满足。
sys.argv = ['fixture', 'placeholder-client']
import ipmi_integration  # noqa: E402
from ipmi_integration import Bmc, SUITE_17, SUITE_3  # noqa: E402

# sol_integration 模块级代码读取 argv[1] 并 pop argv[2]。
sys.argv = ['fixture', 'client', 'agent']
import sol_integration  # noqa: E402


class DesktopSolBmc(sol_integration.SolBmc):
    def __init__(self, mode='normal'):
        super().__init__(mode)
        self.extra = []
        self.after = []
        self.acks = []

    def unpack(self, datagram, payload):
        # IPMI 2.0 6.12.14 permits forward gaps of up to 15 packets.
        sequence = int.from_bytes(datagram[10:14], 'little')
        assert 1 <= (sequence - self.in_sequence) & 0xffffffff <= 15
        self.in_sequence = sequence - 1
        return super().unpack(datagram, payload)

    def command(self, datagram, payload):
        previous_sequence = self.in_sequence
        _, netfn, _, _, sequence, command, data = sol_integration.parse_message(self.unpack(datagram, payload))
        if netfn == 6 and command == 1:
            response = ipmi_integration.DEVICE_ID
        elif netfn == 0 and command == 1:
            response = bytes(4)  # chassis powered off
        elif netfn == 10 and command in (0x20, 0x40):
            response = bytes([0x51, 0, 0]) + bytes(12)
        elif netfn == 10 and command == 0x10:
            response = bytes([0, 1, 0])
        else:
            self.in_sequence = previous_sequence
            return super().command(datagram, payload)
        return self.wrap(sol_integration.build_message(netfn + 1, command, response, sequence))


def main():
    fixed_port = FIXED_PORT
    bmc = DesktopSolBmc('cli')
    if fixed_port:
        import socket
        bmc.socket.close()
        bmc.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bmc.socket.bind(('127.0.0.1', fixed_port))
        bmc.socket.settimeout(0.2)
    bmc.__enter__()
    try:
        print(f'READY {bmc.port}', flush=True)
        # 保持进程存活；测试完成后由调用方终止。
        try:
            sys.stdin.read()
        except Exception:
            pass
    finally:
        bmc.__exit__(None, None, None)


if __name__ == '__main__':
    main()
