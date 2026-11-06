"""ATEN CGI session ownership, JNLP resource acquisition and automatic media probe."""
import argparse
import base64
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

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--c-build', type=Path, required=True)
parser.add_argument('--mode', choices=['console', 'probe', 'unknown', 'rejected', 'brand-only', 'media', 'media-tls', 'live', 'live-tls', 'media-pack', 'media-pack-fallback','resource-host','resource-port','resource-userinfo','encoded-rejected','encoded-unknown','live-ast'], default='probe')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('redfish_fixture', Path(__file__).with_name('redfish_integration.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)
archive = io.BytesIO()
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('libSharedLibrary64.so', fixture(1 if args.mode == 'unknown' else 3))
    z.writestr('libiKVM64.so', mouse_cipher_fixture())

def get(h):
    h.server.events.append(('GET', h.path))
    if h.path == '/redfish/v1/':
        return h.reply(404, b'not available')
    if h.path == '/':
        if args.mode in ('live-tls','media-tls','encoded-rejected','encoded-unknown'):
            check='01' if args.mode=='encoded-unknown' else '00'
            return h.reply(200,('<form name="form1" method="post" action="/cgi/login.cgi"><input name="name" type="text"><input name="pwd" type="text"><button type="button" onclick="javascript: checkform(this)">Login</button><input type="hidden" name="check" value="'+check+'"></form>').encode())
        return h.reply(200, b'<html>ATEN BMC</html>' if args.mode == 'brand-only' else b'<html><form method="post" action="/cgi/login.cgi"><input name="name" type="text"><input name="pwd" type="password"></form></html>')
    assert 'SID=owned-fixture' in h.headers.get('Cookie', ''), h.path
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
        return h.reply(200, b'<script>window.location.href="/";</script>')
    raise AssertionError(h.path)

def post(h):
    h.server.events.append(('POST', h.path))
    assert h.path == '/cgi/login.cgi'
    body = h.rfile.read(int(h.headers['Content-Length']))
    if args.mode in ('live-tls','media-tls','encoded-rejected'):
        fields=urllib.parse.parse_qs(body.decode(),strict_parsing=True)
        assert fields=={'name':[base64.b64encode(b'user').decode()],'pwd':[base64.b64encode(b'test-secret').decode()],'check':['00']},fields
    else:assert body == b'name=user&pwd=test-secret', body
    assert not h.headers.get('Cookie') and not h.headers.get('Authorization')
    if args.mode in ('rejected','encoded-rejected'):
        return h.reply(200, b'<script>window.location.href="/cgi/url_redirect.cgi?url_name=login_alert";</script>')
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
