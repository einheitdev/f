#!/usr/bin/env bash
# Does the masquerade gateway's RETURN path work? Send an outbound flow
# (installs the NAT reply mapping), then a reply from the "internet" to
# the WAN address, and check whether it reaches the LAN host de-NAT'd.
# Assumes gw_topo.sh up has staged the standard masquerade gateway.
set -uo pipefail
lan_mac="$(cat /sys/class/net/lan0/address)"
wan_mac="$(cat /sys/class/net/wan0/address)"
PCAP=/tmp/ftest-return.pcap
rm -f "$PCAP"

# 1. Outbound: LAN 10.0.0.2:40000 -> 203.0.113.9:80 (masq -> 203.0.113.1).
ip netns exec lanhost python3 - "$lan_mac" <<'PY'
import sys
from scapy.all import Ether, IP, TCP, sendp
sendp(Ether(dst=sys.argv[1]) / IP(src="10.0.0.2", dst="203.0.113.9") /
      TCP(sport=40000, dport=80, flags="S"), iface="lan0p",
      count=2, inter=0.1, verbose=0)
PY
sleep 0.3

# 2. Capture on the LAN host while the "internet" replies to the WAN addr.
ip netns exec lanhost timeout 4 tcpdump -i lan0p -c 3 -w "$PCAP" \
  'ip and tcp' >/dev/null 2>&1 &
cap=$!
sleep 0.5
ip netns exec wanhost python3 - "$wan_mac" <<'PY'
import sys
from scapy.all import Ether, IP, TCP, sendp
# reply: internet 203.0.113.9:80 -> WAN 203.0.113.1:40000 (the masq port)
sendp(Ether(dst=sys.argv[1]) / IP(src="203.0.113.9", dst="203.0.113.1") /
      TCP(sport=80, dport=40000, flags="SA"), iface="wan0p",
      count=3, inter=0.2, verbose=0)
PY
wait "$cap" 2>/dev/null

python3 - "$PCAP" <<'PY'
import sys
from scapy.all import rdpcap, IP
try:
    p = [x for x in rdpcap(sys.argv[1]) if IP in x]
except Exception:
    p = []
if not p:
    print("RETURN_DROPPED: nothing reached the LAN host")
else:
    print("RETURN_OK: LAN host saw dst=%s (de-NAT'd)" % p[0][IP].dst)
PY
