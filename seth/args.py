import argparse
from binascii import hexlify

parser = argparse.ArgumentParser(
    description="RDP credential sniffer -- Adrian Vollmer, SySS GmbH 2017")
parser.add_argument('-d', '--debug', dest='debug', action="store_true",
    default=False, help="show debug information")
#  parser.add_argument('-r', '--relay', dest='relay', action="store_true",
#      default=False, help="perform a relay attack")
parser.add_argument('-f', '--fake-server', dest='fake_server', action="store_true",
    default=False, help="perform a 'fake server' attack")
parser.add_argument('-p', '--listen-port', dest='listen_port', type=int,
    default=3389, help="TCP port to listen on (default 3389)")
parser.add_argument('-b', '--bind-ip', dest='bind_ip', type=str, default="",
    help="IP address to bind the fake service to (default all)")
parser.add_argument('-g', '--downgrade', dest='downgrade', type=int,
    default=3, action="store", choices=[0,1,3,11],
    help="downgrade the authentication protocol to this (default 3)")
parser.add_argument('-j', '--inject', dest='inject', type=str,
    required=False, help="command to execute via key press event injection")
parser.add_argument('-c', '--certfile', dest='certfile', type=str,
    required=True, help="path to the certificate file")
parser.add_argument('-k', '--keyfile', dest='keyfile', type=str,
    required=True, help="path to the key file")
parser.add_argument('target_host', type=str,
    help="target host of the RDP service")
parser.add_argument('target_port', type=int, default=3389, nargs='?',
    help="TCP port of the target RDP service (default 3389)")

args = parser.parse_args()

try:
    from hexdump import hexdump
except ImportError:
    if args.debug:
        print("Warning: The python3 module 'hexdump' is missing. "
              "Using hexlify instead.")
    def hexdump(x): print(hexlify(x).decode())
