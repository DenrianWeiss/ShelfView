#!/usr/bin/env python3
"""桌面端验收用本地 RFB 3.8 夹具（None 安全、Raw 帧、64x64 渐变画面）。
用法: rfb_fixture.py <port>；打印 READY 后服务，输入行 EOF/进程终止结束。
"""
import socket
import sys
import threading
import time


def serve(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', port))
    listener.listen(1)
    print(f'READY {port}', flush=True)
    conn, _ = listener.accept()
    with conn:
        stream = conn.makefile('rwb')
        stream.write(b'RFB 003.008\n')
        stream.flush()
        version = stream.read(12)
        assert version == b'RFB 003.008\n', version
        stream.write(bytes([1, 1]))  # 仅 None
        stream.flush()
        selection = stream.read(1)
        assert selection == b'\x01'
        stream.write(b'\x00\x00\x00\x00')  # SecurityResult OK
        stream.flush()
        client_init = stream.read(1)
        assert client_init == b'\x01'
        name = b'bcontrol-rfb-fixture'
        server_init = bytearray()
        server_init += (64).to_bytes(2, 'big') + (64).to_bytes(2, 'big')
        server_init += bytes([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0])
        server_init += len(name).to_bytes(4, 'big') + name
        stream.write(bytes(server_init))
        stream.flush()
        counter = 0
        conn.settimeout(0.2)
        while True:
            try:
                data = stream.read(64)
                if not data:
                    break
            except (TimeoutError, socket.timeout):
                pass
            except OSError:
                break
            # 周期发送一帧 64x64 Raw 更新（像素随 counter 渐变）。
            counter += 1
            pixels = bytearray()
            for y in range(64):
                for x in range(64):
                    pixels += bytes([(x * 4 + counter) & 0xff, (y * 4) & 0xff, 128, 255])
            update = bytearray()
            update += (0).to_bytes(1, 'big') + (0).to_bytes(1, 'big')
            update += (1).to_bytes(2, 'big')
            update += (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
            update += (64).to_bytes(2, 'big') + (64).to_bytes(2, 'big')
            update += (0).to_bytes(4, 'big')  # Raw 编码
            try:
                stream.write(bytes(update) + bytes(pixels))
                stream.flush()
            except OSError:
                break
            time.sleep(0.5)


if __name__ == '__main__':
    serve(int(sys.argv[1]))
