import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

client = sys.argv[1]
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    for mode in ('plain', 'mutual', 'fail'):
        fail = mode == 'fail'
        context.verify_mode = ssl.CERT_REQUIRED if mode == 'mutual' else ssl.CERT_NONE
        if mode == 'mutual':
            context.load_verify_locations(cafile=cert)
        errors = []
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(5)
            def serve():
                try:
                    with listener.accept()[0] as raw:
                        raw.settimeout(3)
                        assert raw.recv(4, socket.MSG_WAITALL) == b'ping'
                        raw.sendall(b'pong')
                        if fail:
                            assert raw.recv(1) == b'\x16'
                            raw.sendall(b'not a TLS server')
                            # A failed upgrade must never send application plaintext.
                            received = b''
                            try:
                                while True:
                                    part = raw.recv(4096)
                                    if not part:
                                        break
                                    received += part
                            except ConnectionResetError:
                                pass
                            assert b'leak' not in received
                        else:
                            with context.wrap_socket(raw, server_side=True) as secure:
                                if mode == 'mutual':
                                    assert secure.getpeercert()
                                assert secure.recv(4) == b'safe'
                                secure.sendall(b'done')
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=serve)
            worker.start()
            result = subprocess.run([client, f'tcp://127.0.0.1:{listener.getsockname()[1]}', str(cert),
                                     'fail' if fail else 'ok'] + ([str(cert), str(key)] if mode == 'mutual' else []), capture_output=True, timeout=8)
            worker.join(5)
            assert not worker.is_alive()
            if errors:
                raise errors[0]
            assert result.returncode == 0, (result.returncode, result.stderr)
