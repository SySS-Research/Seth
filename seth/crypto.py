import struct
import hashlib
import subprocess
import re
from binascii import hexlify, unhexlify

from seth.args import args, hexdump
from seth.consts import TERM_PRIV_KEY

class RC4(object):
    def __init__(self, key):
        x = 0
        self.sbox = list(range(256))
        for i in range(256):
            x = (x + self.sbox[i] + key[i % len(key)]) % 256
            self.sbox[i], self.sbox[x] = self.sbox[x], self.sbox[i]
        self.i = self.j = 0
        self.encrypted_packets = 0


    def decrypt(self, data):
        if self.encrypted_packets >= 4096:
            self.update_key()
        out = []
        for char in data:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.sbox[self.i]) % 256
            self.sbox[self.i], self.sbox[self.j] = self.sbox[self.j], self.sbox[self.i]
            out.append(char ^ self.sbox[(self.sbox[self.i] + self.sbox[self.j]) % 256])
        self.encrypted_packets += 1
        return bytes(bytearray(out))


    def update_key(self):
        print("Updating session keys")
        pad1 = b"\x36"*40
        pad2 = b"\x5c"*48
        # TODO finish this


def reencrypt_client_random(crypto, bytes):
    """Replace the original encrypted client random (encrypted with OUR
    public key) with the client random encrypted with the original public
    key"""

    reenc_client_rand = rsa_encrypt(crypto["client_rand"],
                                    crypto["pubkey"]) + b"\x00"*8
    result = bytes.replace(crypto["enc_client_rand"],
                           reenc_client_rand)
    return result


def generate_rsa_key(keysize):
    p = subprocess.Popen(
        ["openssl", "genrsa", str(keysize)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )
    key_pipe = subprocess.Popen(
        ["openssl", "rsa", "-noout", "-text"],
        stdin=p.stdout,
        stdout=subprocess.PIPE
    )
    p.stdout.close()
    output = key_pipe.communicate()[0]

        # parse the text output
    key = None
    result = {}
    for line in output.split(b'\n'):
        field = line.split(b':')[:2]
        if len(field) == 2 and field[0] in [
            b'modulus',
            b'privateExponent',
            b'publicExponent'
        ]:
            key = field[0].decode()
            result[key] = field[1]
        elif not line[:1] == b" ":
            key = None
        if line[:4] == b" "*4 and key in result:
            result[key] += line[4:]

    for f in ["modulus", "privateExponent"]:
        b = result[f].replace(b':', b'')
        b = unhexlify(b)
        result[f] = int.from_bytes(b, "big")

    m = re.match(b'.* ([0-9]+) ', result['publicExponent'])
    result['publicExponent'] = int(m.groups(1)[0])
    return result


def rsa_encrypt(bytes, key):
    r = int.from_bytes(bytes, "little")
    e = key["publicExponent"]
    n = key["modulus"]
    c = pow(r, e, n)
    return c.to_bytes(2048, "little").rstrip(b"\x00")


def rsa_decrypt(bytes, key):
    s = int.from_bytes(bytes, "little")
    d = key["privateExponent"]
    n = key["modulus"]
    m = pow(s, d, n)
    return m.to_bytes(2048, "little").rstrip(b"\x00")


def is_fast_path(bytes):
    if len(bytes) <= 1: return False
    return bytes[0] % 4 == 0 and bytes[1] in [len(bytes), 0x80]


def decrypt(bytes, From="Client"):
    cleartext = b""
    if is_fast_path(bytes):
        is_encrypted = (bytes[0] >> 7 == 1)
        has_opt_length = (bytes[1] >= 0x80)
        offset = 2
        if has_opt_length:
            offset += 1
        if is_encrypted:
            offset += 8
            cleartext = rc4_decrypt(bytes[offset:], From=From)
    else: # slow path
        offset = 13
        if len(bytes) <= 15: return bytes
        if bytes[offset] >= 0x80: offset += 1
        offset += 1
        security_flags = struct.unpack('<H', bytes[offset:offset+2])[0]
        is_encrypted = (security_flags & 0x0008)
        if is_encrypted:
            offset += 12
            cleartext = rc4_decrypt(bytes[offset:], From=From)

    if not cleartext == b"":
        if args.debug:
            print("Cleartext: ")
            hexdump(cleartext)
        return bytes[:offset] + cleartext
    else:
        return bytes


def sym_encryption_enabled(crypto):
    if "client_rand" in crypto:
        return (not crypto["client_rand"] == b"")
    else:
        return False


def generate_session_keys(crypto):

    # Ch. 5.3.5.1
    def salted_hash(s, i):
        sha1 = hashlib.sha1()
        sha1.update(i + s + crypto["client_rand"] +
                    crypto["server_rand"])
        md5 = hashlib.md5()
        md5.update(s + sha1.digest())
        return md5.digest()

    def final_hash(k):
        md5 = hashlib.md5()
        md5.update(k + crypto["client_rand"] +
                   crypto["server_rand"])
        return md5.digest()


    # Non-Fips, 128bit key

    pre_master_secret = (crypto["client_rand"][:24] +
            crypto["server_rand"][:24])
    master_secret = (salted_hash(pre_master_secret, b"A") +
                     salted_hash(pre_master_secret, b"BB") +
                     salted_hash(pre_master_secret, b"CCC"))
    session_key_blob = (salted_hash(master_secret, b"X") +
                        salted_hash(master_secret, b"YY") +
                        salted_hash(master_secret, b"ZZZ"))
    mac_key, server_encrypt_key, server_decrypt_key = [
        session_key_blob[i*16:(i+1)*16] for i in range(3)
    ]
    server_encrypt_key = final_hash(server_encrypt_key)
    server_decrypt_key = final_hash(server_decrypt_key)
    client_encrypt_key = server_decrypt_key
    client_decrypt_key = server_encrypt_key

    crypto["mac_key"] = mac_key
    crypto["server_encrypt_key"] = server_encrypt_key
    crypto["server_decrypt_key"] = server_decrypt_key
    crypto["client_encrypt_key"] = client_encrypt_key
    crypto["client_decrypt_key"] = client_decrypt_key

    # TODO handle shorter keys than 128 bit
    print("Session keys generated")
    init_rc4_sbox(crypto)


def init_rc4_sbox(crypto):
    print("Initializing RC4 s-box")
    # TODO: get rid of global variables
    global RC4_CLIENT
    global RC4_SERVER
    RC4_CLIENT = RC4(crypto["server_decrypt_key"])
    RC4_SERVER = RC4(crypto["client_decrypt_key"])


def rc4_decrypt(data, From="Client"):
    if From == "Client":
        return RC4_CLIENT.decrypt(data)
    else:
        return RC4_SERVER.decrypt(data)


def sign_certificate(cert, sign_len):
    """Signs the certificate with the private key"""
    m = hashlib.md5()
    m.update(cert)
    m = m.digest() + b"\x00" + b"\xff"*45 + b"\x01"
    m = int.from_bytes(m, "little")
    d = int.from_bytes(TERM_PRIV_KEY["d"], "little")
    n = int.from_bytes(TERM_PRIV_KEY["n"], "little")
    s = pow(m, d, n)
    return s.to_bytes(sign_len, "little")


