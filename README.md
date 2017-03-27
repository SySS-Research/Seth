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

Disclaimer
----------

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
