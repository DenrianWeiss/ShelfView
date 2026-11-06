"""Synthetic HTTPS Appweb XML login, owner cleanup and descriptor discovery."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import socket
import ssl
import struct
import threading
import urllib.parse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--c-build', type=Path, required=True)
parser.add_argument('--mode', choices=['success', 'duplicate', 'rejected', 'bad-csrf', 'brand-only', 'media', 'media-busy', 'media-race', 'media-uncertain'], default='success')
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('reference', root / 'tests/redfish_integration.py')
reference = importlib.util.module_from_spec(spec)
sys.argv = ['reference', str(args.c_build / 'bcontrol-redfish-client')]
spec.loader.exec_module(reference)

def get(h):
    uri = urllib.parse.urlsplit(h.path)
    h.server.events.append(('GET', uri.path))
    if uri.path == '/redfish/v1/':
        return h.reply(404, {})
    if uri.path == '/':
        return h.reply(302, b'', [('Location', '/login.html')])
    if uri.path == '/login.html':
        body = b'''<html><title>Unknown OEM</title><script>
function sendLoginRequest() {
var form=document.auth;var url='data/login';
var postData='user='+encodeURIComponent(fullUserName)+'&password='+encodeSetValue(fullPassword);
sendPost(url,postData,loginRequestChange);return(false);}
</script><form action="" name="auth" method="post" onsubmit="sendLoginRequest();"><input name="user" type="text"><input name="password" type="password"></form></html>'''
        if args.mode == 'brand-only':
            body = b'<html>Avocent MergePoint /data/login _appwebSessionId_</html>'
        return h.reply(200, body)
    if h.headers.get('Cookie') != '_appwebSessionId_=web-fixture':
        raise RuntimeError('Missing own session cookie')
    if uri.path == '/index.html':
        if uri.query and (uri.query != 'ST1=one' or h.headers.get('ST2') != 'two'):
            raise RuntimeError('Wrong CSRF scope')
        tokens = b'new CSRFHandler("ST1","one","ST2","two",true);' if args.mode != 'bad-csrf' else b'var unrelated=1;'
        return h.reply(200, b'<html><script>' + tokens + b'''
function getJavaPluginParameter(){var ipAddrAndFormat=getIPAddressAndFormat('localhost');var cache=new Date().getTime();return(ipAddrAndFormat+"@"+cache);}
function launch(){var params=getJavaPluginParameter();window.open(top.G_objCSRFHandler.getACSRFProtectedUri("viewer.jnlp("+params+")"),'hidden_frame');}
function media(){var params=getJavaPluginParameter();window.open(top.G_objCSRFHandler.getACSRFProtectedUri("/data?type=jnlp&get=vmStart("+params+")"),'hidden_frame');}
</script></html>''')
    if uri.path.startswith('/viewer.jnlp('):
        if uri.query != 'ST1=one' or h.headers.get('ST2') != 'two':
            raise RuntimeError('Missing CSRF tokens on startup')
        return h.reply(200, b'<jnlp><application-desc main-class="com.avocent.kvm.client.Main"><argument>ip=localhost</argument><argument>user=ticket</argument><argument>passwd=secret</argument><argument>kmport=2068</argument><argument>vport=2068</argument><argument>apcp=1</argument></application-desc></jnlp>')
    if uri.path == '/data':
        query = urllib.parse.parse_qs(uri.query)
        assert query['type'] == ['jnlp'] and query['get'][0].startswith('vmStart(localhost@0@')
        assert query['ST1'] == ['one'] and h.headers.get('ST2') == 'two'
        return h.reply(200, f'<jnlp><application-desc main-class="com.avocent.vm.VirtualMedia"><argument>ip=localhost</argument><argument>user=ticket</argument><argument>password=secret</argument><argument>port={media_port}</argument></application-desc></jnlp>'.encode())
    if uri.path == '/data/logout':
        return h.reply(200, b'<root><status>0</status></root>')
    raise RuntimeError('Unexpected GET: ' + uri.path)

def post(h):
    h.server.events.append(('POST', h.path))
    body = h.rfile.read(int(h.headers.get('Content-Length', 0)))
    if h.path != '/data/login' or body != b'user=user&password=test-secret':
        raise RuntimeError('Unexpected form or login replay')
    if any(h.headers.get(k) for k in ('Cookie', 'Authorization', 'X-Auth-Token')):
        raise RuntimeError('Login inherited authentication')
    result = 7 if args.mode == 'duplicate' else 1 if args.mode == 'rejected' else 0
    h.reply(200, f'<root><status>0</status><authResult>{result}</authResult><forwardUrl>index.html</forwardUrl></root>'.encode(), [('Set-Cookie', '_appwebSessionId_=web-fixture; Path=/; Secure')])

reference.Handler.do_GET, reference.Handler.do_POST = get, post
reference.Redfish.setUpClass()
media_port = 0
media_errors = []
def media_server(listener):
    def exact(conn, n):
        data = b''
        while len(data) < n:
            part = conn.recv(n-len(data))
            if not part: raise EOFError()
            data += part
        return data
    def frame(conn):
        while True:
            head = exact(conn, 12)
            magic, size, kind, slot = struct.unpack('>4sIHH', head)
            assert magic == b'AVMP' and 12 <= size <= 131104
            body = exact(conn, size-12)
            if kind != 0x400: return kind, slot, body
    def send(conn, kind, slot=0, body=b''):
        conn.sendall(struct.pack('>4sIHH', b'AVMP', 12+len(body), kind, slot)+body)
    def slots(conn, mounted):
        send(conn, 0x8200, body=struct.pack('>HBBH', 1, 2, int(mounted), 1))
    try:
        conn, _ = listener.accept(); conn.settimeout(10)
        request = exact(conn, 53)
        assert request[:4] == b'APCP' and request[12] == 2 and request[19] == 4
        conn.sendall(b'APCP'+struct.pack('>IHHBBIH',53,0x8100,0,0,0,4,0)+bytes(33))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(reference.Redfish.root / 'cert', reference.Redfish.root / 'key')
        with ctx.wrap_socket(conn, server_side=True) as conn:
            kind, slot, body = frame(conn)
            assert kind == 0x100 and slot == 0 and len(body) == 141
            assert body[0] == 6 and body[1:7] == b'ticket' and body[97:103] == b'secret' and body[-1] == 0
            send(conn, 0x8100, body=bytes(99))
            assert frame(conn)[:2] == (0x200,65535); slots(conn,args.mode == 'media-busy')
            if args.mode == 'media-busy':
                assert conn.recv(1) == b''; return
            kind, slot, body = frame(conn)
            assert (kind,slot) == (0x210,0)
            assert struct.unpack('>IIBBH',body[:12]) == (2048,1024,1,255,20)
            assert body[12:] == bytes.fromhex('0012010100140100000000000014aa0000000400')
            if args.mode == 'media-race':
                send(conn,0x8410,body=struct.pack('>I',5)); assert conn.recv(1) == b''; return
            send(conn,0x8410,body=bytes(4))
            assert frame(conn)[:2] == (0x200,65535); slots(conn,True)
            send(conn,0x8300,body=struct.pack('>III',7,5,2))
            position = 7
            for count in (2,2,1):
                kind, slot, body = frame(conn)
                assert (kind,slot) == (0x300,0) and struct.unpack('>II',body[:8]) == (position,count)
                assert body[8:] == bytes((position*2048+i)%251 for i in range(count*2048))
                position += count
            assert frame(conn) == (0x410,0,bytes(4))
            assert frame(conn) == (0x220,0,b'')
            if args.mode == 'media-uncertain': return
            send(conn,0x8410,body=bytes(4))
            assert frame(conn)[:2] == (0x200,65535); slots(conn,False)
    except BaseException as exc: media_errors.append(exc)
    finally: listener.close()
media_thread = None
if args.mode.startswith('media'):
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen();listener.settimeout(15)
    media_port=listener.getsockname()[1]
    media_thread=threading.Thread(target=media_server,args=(listener,),daemon=True);media_thread.start()
try:
    with reference.Redfish().fixture() as server:
        server.events = []
        subprocess.run([str(args.c_build.resolve() / 'bcontrol-console-prepare-client'),
            'https://localhost:' + str(server.server_port), str(reference.Redfish.root / 'cert'),
            args.mode if args.mode.startswith('media') else 'avocent' if args.mode == 'success' else 'failure'], check=True, timeout=20)
        events = server.events
        assert events.count(('POST', '/data/login')) == (0 if args.mode == 'brand-only' else 1), events
        assert events.count(('GET', '/data/logout')) == (1 if args.mode in ('success', 'media', 'media-busy', 'media-race', 'media-uncertain', 'bad-csrf') else 0), events
        assert sum(method == 'GET' and path.startswith('/viewer.jnlp(') for method, path in events) == (1 if (args.mode == 'success' or args.mode.startswith('media')) else 0), events
        if media_thread:
            media_thread.join(12)
            assert not media_thread.is_alive() and not media_errors, media_errors
        print('Appweb fixture passed:', args.mode)
finally:
    reference.Redfish.tearDownClass()
