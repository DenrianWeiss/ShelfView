"""ATEN CGI session ownership, JNLP resource acquisition and automatic media probe."""
import argparse
import base64
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import urllib.parse
import zipfile
import ssl
import socket
import struct
import threading
from aten_native_fixture import fixture, mouse_cipher_fixture
from apple_socks5 import exact, ws_receive, ws_send

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--c-build', type=Path, required=True)
parser.add_argument('--mode', choices=['console', 'probe', 'unknown', 'rejected', 'brand-only', 'media', 'media-tls', 'live', 'live-tls', 'media-pack', 'media-pack-fallback','resource-host','resource-port','resource-userinfo','encoded-rejected','encoded-unknown','live-ast','supermicro'], default='probe')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('redfish_fixture', Path(__file__).with_name('redfish_integration.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)
archive = io.BytesIO()
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('libSharedLibrary64.so', fixture(1 if args.mode == 'unknown' else 3))
    z.writestr('libiKVM64.so', mouse_cipher_fixture())

ticket = b'0123456789abcdefghijk+/='
console_page = '/cgi/url_redirect.cgi?url_name=man_remoteconsole'
bootstrap = '/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap'
jnlp = '/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk'

def console_exchange(send, receive, credentials):
    for outbound, inbound in ((b'RFB 055.008\n', b'RFB 055.008\n'), (b'\x01\x10', b'\x10'),
                              (bytes(24), credentials), (bytes(4), b'\x01')):
        send(outbound)
        assert receive(len(inbound)) == inbound
    init = bytearray(36)
    struct.pack_into('>HH', init, 0, 2, 2)
    send(init)
    assert receive(10)[0] == 3
    frame = bytearray(42)
    frame[3] = 1
    frame[9] = frame[11] = 2
    frame[15] = 0x59
    frame[23] = 18
    frame[24] = 1
    frame[34:] = bytes.fromhex('007c007c007c007c')
    send(frame)
    assert receive(10)[0] == 3

def get(h):
    h.server.events.append(('GET', h.path))
    if h.path == '/redfish/v1/':
        return h.reply(404, b'not available')
    if h.path == '/':
        if args.mode == 'supermicro' and h.headers.get('Upgrade') == 'websocket':
            assert h.server.mode == 1 and 'SID=owned-fixture' in h.headers.get('Cookie', '')
            assert h.headers['Origin'] == f'https://localhost:{h.server.server_port}'
            assert h.headers['Sec-WebSocket-Protocol'] == 'binary'
            accept = base64.b64encode(hashlib.sha1((h.headers['Sec-WebSocket-Key'] +
                '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            h.send_response(101)
            for name, value in [('Upgrade', 'websocket'), ('Connection', 'Upgrade'),
                                ('Sec-WebSocket-Accept', accept), ('Sec-WebSocket-Protocol', 'binary')]:
                h.send_header(name, value)
            h.end_headers()
            h.close_connection = True
            h.connection.settimeout(5)
            try:
                console_exchange(lambda data: ws_send(h.connection, data), lambda _: ws_receive(h.connection), ticket + bytes(24))
            except Exception as error:
                errors.append(error)
            return
        if args.mode in ('live-tls','media-tls','encoded-rejected','encoded-unknown'):
            check='01' if args.mode=='encoded-unknown' else '00'
            return h.reply(200,('<form name="form1" method="post" action="/cgi/login.cgi"><input name="name" type="text"><input name="pwd" type="text"><button type="button" onclick="javascript: checkform(this)">Login</button><input type="hidden" name="check" value="'+check+'"></form>').encode())
        return h.reply(200, b'<html>ATEN BMC</html>' if args.mode == 'brand-only' else b'<html><form method="post" action="/cgi/login.cgi"><input name="name" type="text"><input name="pwd" type="password"></form></html>')
    assert 'SID=owned-fixture' in h.headers.get('Cookie', ''), h.path
    if h.path == console_page:
        if args.mode != 'supermicro':
            return h.reply(404, b'not available')
        return h.reply(200, b'<script>var pars = "op=GET_IKVM_INTERFACE.XML&r=(0,0)";</script>'
                            b'<script>SmcCsrfInsert("CSRF-TOKEN", "fixture-token=");</script>')
    if args.mode == 'supermicro' and h.path == bootstrap:
        assert h.server.mode == 1
        return h.reply(200, b'<input type="hidden" id="entry_value" value="' + ticket + b'">')
    if args.mode == 'supermicro' and h.path == jnlp:
        assert h.server.mode == 0
        pem = (reference.Redfish.root / ('other-cert' if h.server.wrong_pin else 'cert')).read_text()
        values = ['https://localhost/', 'iKVM.jar'] + ['native.jar'] * 8 + [
            'localhost', 'ticket', 'secret', 'null', '63630', '63631', '0', '0', '1', str(console_port), '623', '1', pem]
        xml = ('<jnlp><resources><jar href="iKVM.jar"/></resources>'
               '<application-desc main-class="tw.com.aten.ikvm.KVMMain">' +
               ''.join('<argument>' + value + '</argument>' for value in values) + '</application-desc></jnlp>')
        return h.reply(200, xml.encode())
    if h.path == '/cgi/url_redirect.cgi?url_name=mainmenu':
        return h.reply(200, b'<a href="/cgi/url_redirect.cgi?url_name=man_ikvm&amp;url_type=jwsk">Console</a>')
    if h.path == '/cgi/url_redirect.cgi?url_name=man_ikvm&url_type=jwsk':
        xml = ('''<jnlp><resources><jar href="iKVM.jar"/></resources>
<resources os="Linux" arch="amd64"><nativelib href="liblinux.jar"/></resources>
<application-desc main-class="tw.com.aten.ikvm.KVMMain"><argument>localhost</argument><argument>ticket</argument><argument>secret</argument><argument>null</argument><argument>{console_port}</argument><argument>{media_port}</argument><argument>0</argument><argument>0</argument></application-desc></jnlp>'''.format(media_port=media_port,console_port=console_port)).encode()
        if args.mode in ('media-tls','live-tls'):
            prefix=b'<argument>http://localhost/</argument><argument>iKVM.jar</argument>'+b'<argument>native.jar</argument>'*8
            xml=xml.replace(b'<argument>localhost</argument>',prefix+b'<argument>localhost</argument>')
            xml=xml.replace(b'</application-desc>',f'<argument>1</argument><argument>{console_port}</argument><argument>{media_port}</argument><argument>1</argument></application-desc>'.encode())
        if args.mode in ('media-pack','media-pack-fallback'):xml=xml.replace(b'<resources>',b'<resources><property name="jnlp.packEnabled" value="true"/>',1)
        if args.mode=='live-tls':xml=xml.replace(b'<jnlp>',f'<jnlp codebase="https://localhost:{h.server.server_port}/assets">'.encode())
        if args.mode=='media-pack-fallback':xml=xml.replace(b'<jnlp>',b'<jnlp codebase="http://localhost/assets/">')
        if args.mode.startswith('resource-'):
            base={'resource-host':'https://elsewhere.invalid/','resource-port':'https://localhost:1/','resource-userinfo':f'https://user@localhost:{h.server.server_port}/'}[args.mode]
            xml=xml.replace(b'<jnlp>',f'<jnlp codebase="{base}">'.encode())
        return h.reply(200,xml)
    if h.path in ('/iKVM.jar','/assets/iKVM.jar'):
        return h.reply(200,identity.getvalue())
    if h.path in ('/liblinux.jar.pack.gz','/assets/liblinux.jar.pack.gz'):
        if args.mode=='media-pack-fallback':return h.reply(404,b'unpacked only')
        return h.reply(200,Path(__file__).with_name('fixtures').joinpath('aten/resources.pack.gz').read_bytes())
    if h.path in ('/liblinux.jar','/assets/liblinux.jar'):
        if args.mode=='media-pack':return h.reply(404,b'packed only')
        return h.reply(200, archive.getvalue())
    if h.path == '/cgi/logout.cgi':
        if args.mode == 'live-tls':
            return h.reply(200, b'<meta http-equiv="refresh" content="0;URL=/"><script>if (window != top) top.location.href = location.href;</script>')
        return h.reply(200, b'<script>window.location.href="/";</script>')
    raise AssertionError(h.path)

def post(h):
    h.server.events.append(('POST', h.path))
    body = h.rfile.read(int(h.headers['Content-Length']))
    if args.mode == 'supermicro' and h.path == '/cgi/ipmi.cgi':
        assert 'SID=owned-fixture' in h.headers.get('Cookie', '')
        assert h.headers['CSRF-TOKEN'] == 'fixture-token='
        assert urllib.parse.parse_qs(body.decode()) == {'op': ['GET_IKVM_INTERFACE.XML'], 'r': ['(0,0)']}
        return h.reply(200, f'<IPMI><IKVM_INFO ikvm_interface="{h.server.mode}"/></IPMI>'.encode())
    assert h.path == '/cgi/login.cgi'
    if args.mode in ('live-tls','media-tls','encoded-rejected'):
        fields=urllib.parse.parse_qs(body.decode(),strict_parsing=True)
        assert fields=={'name':[base64.b64encode(b'user').decode()],'pwd':[base64.b64encode(b'test-secret').decode()],'check':['00']},fields
    else:assert body == b'name=user&pwd=test-secret', body
    assert not h.headers.get('Cookie') and not h.headers.get('Authorization')
    if args.mode in ('rejected','encoded-rejected'):
        return h.reply(200, b'<script>window.location.href="/cgi/url_redirect.cgi?url_name=login_alert";</script>')
    if args.mode == 'live-tls':
        return h.reply(200, b'<script><!--\nself.location = "../cgi/url_redirect.cgi?url_name=mainmenu";\n--></script>',
                       [('Set-Cookie', 'SID=owned-fixture; Path=/; Secure')])
    return h.reply(200, b'<script>window.location.href="/cgi/url_redirect.cgi?url_name=mainmenu";</script>', [('Set-Cookie', 'SID=owned-fixture; Path=/; Secure')])

reference.Handler.do_GET, reference.Handler.do_POST = get, post
reference.Redfish.setUpClass()
identity=io.BytesIO()
with zipfile.ZipFile(identity,'w',zipfile.ZIP_DEFLATED) as z:
    z.writestr('res/client.crt',(reference.Redfish.root/'cert').read_bytes())
    z.writestr('res/client.key',(reference.Redfish.root/'key').read_bytes())
media_port=623
console_port=5900
errors=[]
worker=None
if args.mode == 'supermicro':
    subprocess.run(['openssl', 'req', '-new', '-x509', '-key', str(reference.Redfish.root/'key'),
                    '-subj', '/CN=wrong-peer', '-days', '1', '-out', str(reference.Redfish.root/'other-cert')],
                   check=True, capture_output=True)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(15)
    console_port = listener.getsockname()[1]
    def serve_java():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(reference.Redfish.root/'cert', reference.Redfish.root/'key')
            with listener.accept()[0] as conn:
                conn.settimeout(5)
                with context.wrap_socket(conn, server_side=True) as wire:
                    console_exchange(wire.sendall, lambda size: exact(wire, size), b'ticket'.ljust(24, b'\0') + b'secret'.ljust(24, b'\0'))
            with listener.accept()[0] as conn:
                conn.settimeout(5)
                with context.wrap_socket(conn, server_side=True) as wire:
                    try:
                        assert not wire.recv(1)
                    except ConnectionResetError:
                        pass
        except Exception as error:
            errors.append(error)
        finally:
            listener.close()
    worker = threading.Thread(target=serve_java, daemon=True)
    worker.start()
if args.mode in ('media','media-tls','live','live-tls','live-ast','media-pack','media-pack-fallback'):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(15)
    if args.mode.startswith('live'):console_port=listener.getsockname()[1]
    else:media_port=listener.getsockname()[1]
    def serve():
        def exact(c,n):
            b=b''
            while len(b)<n:
                part=c.recv(n-len(b))
                if not part:raise EOFError()
                b+=part
            return b
        def packet(c):
            h=exact(c,8);return h,exact(c,struct.unpack_from('<I',h,4)[0])
        def send(c,endpoint,tag,data):c.sendall(bytes([endpoint,0,0,tag])+struct.pack('<I',len(data))+data)
        try:
            with listener.accept()[0] as c:
                c.settimeout(10)
                if args.mode in ('media-tls','live-tls'):
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(reference.Redfish.root/'cert',reference.Redfish.root/'key')
                    context.load_verify_locations(cafile=reference.Redfish.root/'cert');context.verify_mode=ssl.CERT_REQUIRED
                    c=context.wrap_socket(c,server_side=True)
                    assert c.getpeercert()
                if args.mode.startswith('live'):
                    c.sendall(b'RFB 003.008\n');assert exact(c,12)==b'RFB 003.008\n'
                    c.sendall(b'\x01\x10');assert exact(c,1)==b'\x10'
                    c.sendall(bytes(24));assert exact(c,48)==b'ticket'+bytes(18)+b'secret'+bytes(18)
                    c.sendall(bytes(4));assert exact(c,1)==b'\x01'
                    init=bytearray(36);struct.pack_into('>HH',init,0,2,2);init[33]=1;c.sendall(init)
                    assert exact(c,10)[0]==3
                    c.sendall(bytes([0x37,1,1,0]))
                    frame=bytearray(42);frame[3]=1;frame[9]=2;frame[11]=2;frame[15]=0x59;frame[23]=18;frame[24]=1
                    frame[34:]=bytes.fromhex('007c007c007c007c')
                    if args.mode=='live-ast':
                        bits='0101'+'1'+'00'+format(82,'08b')+format(90,'08b')+format(240,'08b')+'1001'
                        bits=bits.ljust(64,'0')
                        payload=bytes([0,0,1,188])+b''.join(int(bits[i:i+32],2).to_bytes(4,'little') for i in (0,32))
                        frame=frame[:24]+payload;frame[15]=0x57;struct.pack_into('>I',frame,20,len(payload))
                    c.sendall(frame)
                    assert exact(c,10)[0]==3
                    for down,usage in ((1,4),(0,4),(1,0xe1),(1,4),(0,4),(0,0xe1),
                                       (1,0xe1),(1,0x1e),(0,0x1e),(0,0xe1)):
                        key=exact(c,18);assert key[0]==4 and key[2]==down and int.from_bytes(key[5:9],'big')==usage
                    pointer=exact(c,18);assert pointer[:2]==bytes([5,1])
                    plain=subprocess.run(['openssl','enc','-d','-aes-128-cbc','-nopad','-K','2b7e151628aed2a6abf7158809cf4f3c','-iv','000102030405060708090a0b0c0d0e0f'],input=pointer[2:],capture_output=True,check=True).stdout
                    assert plain[:5]==bytes([1,0,1,0,1]), plain[:5]
                    for mask in (9,1):
                        pointer=exact(c,18);assert pointer[:2]==bytes([5,1])
                        plain=subprocess.run(['openssl','enc','-d','-aes-128-cbc','-nopad','-K','2b7e151628aed2a6abf7158809cf4f3c','-iv','000102030405060708090a0b0c0d0e0f'],input=pointer[2:],capture_output=True,check=True).stdout
                        assert plain[:5]==bytes([mask,0,1,0,1]), plain[:5]
                    # Closing may send key releases before closing the stream.
                    while c.recv(4096):pass
                    return
                setup=exact(c,226)
                assert setup[:8]==bytes.fromhex('008000012c000000')
                key=b'BX80570E3110Q814A447';table=list(range(256));j=0
                for i in range(256):
                    j=(j+table[i]+key[i%len(key)])%256;table[i],table[j]=table[j],table[i]
                plain=bytearray(setup[8:]);i=j=0
                for n in range(len(plain)):
                    i=(i+1)%256;j=(j+table[i])%256;table[i],table[j]=table[j],table[i]
                    plain[n]^=table[(table[i]+table[j])%256]
                assert plain[:6]==b'ticket' and plain[16:22]==b'secret' and plain[40:44]==bytes.fromhex('83030000')
                send(c,0,2,bytes(9))
                h,b=packet(c);assert h[3]==7 and b==bytes.fromhex('0603011002200330')
                cbw=bytearray(31);cbw[:4]=b'USBC';struct.pack_into('<II',cbw,4,7,5*2048);cbw[12]=0x80;cbw[14]=10;cbw[15]=0x28;cbw[23]=5
                send(c,0x11,0,cbw)
                h,b=packet(c);assert h[0]==0x22 and b==bytes(i%251 for i in range(5*2048))
                h,b=packet(c);assert h[3]==0xff and b==b'USBS'+struct.pack('<II',7,0)+b'\0'
                h,b=packet(c);assert h[3]==5 and not b
                send(c,0,6,b'\0')
        except BaseException as error:errors.append(error)
        finally:listener.close()
    worker=threading.Thread(target=serve,daemon=True);worker.start()
try:
    with reference.Redfish().fixture() as server:
        server.events = []
        if args.mode == 'supermicro':
            for current_mode, path, wrong_pin in ((1, bootstrap, False), (0, jnlp, False), (0, jnlp, True), (2, None, False)):
                server.mode = current_mode
                server.wrong_pin = wrong_pin
                server.events.clear()
                subprocess.run([str(args.c_build.resolve() / 'bcontrol-console-prepare-client'),
                    f'https://localhost:{server.server_port}', str(reference.Redfish.root / 'cert'),
                    'aten-view' if path and not wrong_pin else 'failure-live'], timeout=20, check=True)
                assert server.events.count(('POST', '/cgi/ipmi.cgi')) == 1, server.events
                assert server.events.count(('GET', '/cgi/logout.cgi')) == 1, server.events
                assert (('GET', bootstrap) in server.events) == (current_mode == 1), server.events
                assert (('GET', jnlp) in server.events) == (current_mode == 0), server.events
            worker.join(10)
            assert not worker.is_alive() and not errors, errors
            raise SystemExit(0)
        mode = 'aten-live' if args.mode.startswith('live') else 'aten-media' if args.mode in ('media','media-tls','media-pack','media-pack-fallback') else 'aten' if args.mode == 'console' else 'aten-probe' if args.mode == 'probe' else 'failure'
        # Unknown media must exercise media preparation rather than console preparation.
        if args.mode == 'unknown': mode = 'aten-probe-failure'
        result = subprocess.run([str(args.c_build.resolve() / 'bcontrol-console-prepare-client'),
                        'https://localhost:' + str(server.server_port), str(reference.Redfish.root / 'cert'), mode], timeout=20)
        assert result.returncode == 0, server.events
        events = server.events
        prefix="/assets" if args.mode in ("live-tls","media-pack-fallback") else ""
        assert events.count(('POST', '/cgi/login.cgi')) == (args.mode not in ('brand-only','encoded-unknown')), events
        assert events.count(('GET', '/cgi/logout.cgi')) == (args.mode in ('console', 'probe', 'unknown', 'media', 'media-tls','live','live-tls','live-ast','media-pack','media-pack-fallback','resource-host','resource-port','resource-userinfo')), events
        assert events.count(('GET', prefix+'/liblinux.jar')) == (args.mode in ('console', 'probe', 'unknown', 'media', 'media-tls','live','live-tls','live-ast','media-pack-fallback')), events
        if worker:
            worker.join(12)
            assert not worker.is_alive() and not errors, errors
        assert events.count(('GET',prefix+'/iKVM.jar')) == (args.mode in ('media-tls','live-tls')), events
        assert events.count(('GET',prefix+'/liblinux.jar.pack.gz')) == (args.mode in ('media-pack','media-pack-fallback')), events
        if args.mode=='media-pack-fallback':
            assert events.index(('GET',prefix+'/liblinux.jar.pack.gz')) < events.index(('GET',prefix+'/liblinux.jar')), events
        print('ATEN web fixture passed:', args.mode)
finally:
    reference.Redfish.tearDownClass()
