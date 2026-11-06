import struct

# Synthetic ELF with only the inspected symbol/branch shapes and ISO label.
def fixture(device=3):
    b = bytearray(2048)
    b[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<H', b, 18, 62)
    struct.pack_into('<Q', b, 40, 64)
    struct.pack_into('<HH', b, 58, 64, 4)
    def section(i, kind, va, offset, size, link=0, stride=0):
        struct.pack_into('<IIQQQQIIQQ', b, 64+i*64, 0, kind, 0, va, offset, size, link, 0, 1, stride)
    section(1, 1, 0x1000, 512, 512)
    section(2, 3, 0, 1100, 100)
    section(3, 11, 0, 1200, 72, 2, 24)
    strings = b'\0GetFileDevStr\0FillUSBPlugInPkt\0'
    b[1100:1100+len(strings)] = strings
    struct.pack_into('<IBBHQQ', b, 1224, 1, 2, 0, 1, 0x1000, 128)
    struct.pack_into('<IBBHQQ', b, 1248, 15, 2, 0, 1, 0x1100, 128)
    prefix = bytes.fromhex('55 48 89 e5 48 83 ec 20 48 89 75 f0 40 88 7d ff 0f b6 45 ff 83 e8 40 88 45 ef 80 7d ef 04')
    b[512:512+len(prefix)] = prefix
    b[561:564] = bytes.fromhex('48 8d 05')
    struct.pack_into('<i', b, 564, 0x1180 - 0x1038)
    struct.pack_into('<i', b, 896, 0x1060 - 0x1180)
    b[608:615] = bytes.fromhex('48 8b 7d f0 48 8d 15')
    struct.pack_into('<i', b, 615, 0x1190 - 0x106b)
    b[912:921] = b'ISO File\0'
    code = bytes.fromhex('80 7d c7 40 74 02 eb 0d 48 8b 45 f0 48 83 c0 31 c6 00') + bytes([device])
    b[768:768+len(code)] = code
    return b

def mouse_fixture():
    b=fixture()
    name=b"\0_ZN8RFBMouse13ProcMouseInfoEv\0"
    b[1100:1200]=name.ljust(100,b"\0")
    struct.pack_into('<IBBHQQ',b,1224,1,2,0,1,0x1000,72)
    b[1248:1272]=bytes(24)
    code=bytes.fromhex("53 48 8b 47 08 48 89 fb 48 8b 78 08 e8 00 00 00 00 0f b6 c0 89 43 18 48 8b 43 08 48 8b 78 08 e8 00 00 00 00 0f b6 c0 89 43 14 48 8b 43 08 48 8b 78 08 e8 00 00 00 00 0f b6 c0 c6 43 10 01 89 43 1c b8 01 00 00 00 5b c3")
    b[512:584]=code
    for offset in (13,32,51):struct.pack_into('<i',b,512+offset,0x1180-(0x1000+offset+4))
    return b

def mouse_cipher_fixture():
    b=mouse_fixture()+bytearray(2048)
    struct.pack_into('<H',b,60,5)
    struct.pack_into('<Q',b,64+64+32,1024)
    strings=b"\0_ZN8RFBMouse13ProcMouseInfoEv\0_ZN10RFBKMCryto21RFB_AES128_EventCrytoEPhS0_\0_ZN10RFBKMCryto10SW_AES_CBCEiiPhiS0_S0_S0_\0"
    b[1600:1600+len(strings)]=strings
    struct.pack_into('<Q',b,64+128+24,1600);struct.pack_into('<Q',b,64+128+32,len(strings))
    b[1900:1972]=b[1200:1272]
    struct.pack_into('<Q',b,64+192+24,1900);struct.pack_into('<Q',b,64+192+32,96)
    struct.pack_into('<IBBHQQ',b,1948,strings.index(b'_ZN10RFBKMCryto21'),2,0,1,0x1100,531)
    cbc=strings.index(b'_ZN10RFBKMCryto10')
    struct.pack_into('<IBBHQQ',b,1972,cbc,2,0,0,0,0)
    code=bytearray(531)
    pieces={0x42:'4c8d4c2410',0x51:'41b001',0xd6:'488d442470',0xfc:'31f6',0x18c:'31d2',0x201:'4889442408e8'}
    used=set()
    for at,value in pieces.items():
        value=bytes.fromhex(value);code[at:at+len(value)]=value;used.update(range(at,at+len(value)))
    used.update(range(0x207,0x20b))
    stores=list(zip(range(0x10,0x20),bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')))+list(zip(range(0x70,0x80),range(16)))
    at=0
    for stack,value in stores:
        while any(i in used for i in range(at,at+5)):at+=1
        code[at:at+5]=bytes([0xc6,0x44,0x24,stack,value]);used.update(range(at,at+5));at+=5
    struct.pack_into('<i',code,0x207,0x1378-(0x1100+0x20b))
    b[768:1299]=code
    b[1400:1402]=bytes.fromhex('ff25');struct.pack_into('<i',b,1402,0x2000-(0x1378+6))
    struct.pack_into('<IIQQQQIIQQ',b,64+256,0,4,0,0,2100,24,3,0,8,24)
    struct.pack_into('<QQq',b,2100,0x2000,(3<<32)|7,0)
    return b
