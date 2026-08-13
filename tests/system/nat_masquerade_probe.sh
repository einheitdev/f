#!/usr/bin/env bash
# Inject a TCP SYN from the LAN host and report the source IP seen on
# the WAN side. With masquerade working the captured src is the WAN
# address (203.0.113.1); if masquerade is a no-op the internal source
# (10.0.0.2) leaks — the observable signature of the fwl_nat_cfg bug.
#
# Assumes gw_topo.sh up has already staged the topology + fd.
set -uo pipefail

PCAP=/tmp/ftest-wan.pcap
lan_mac="$(cat /sys/class/net/lan0/address)"

rm -f "$PCAP"
ip netns exec wanhost timeout 4 tcpdump -i wan0p -c 3 -w "$PCAP" \
  'ip and tcp' >/dev/null 2>&1 &
cap=$!
sleep 0.6

ip netns exec lanhost python3 - "$lan_mac" <<'PY'
import sys
from scapy.all import Ether, IP, TCP, sendp
lan_mac = sys.argv[1]
pkt = (Ether(dst=lan_mac) /
       IP(src="10.0.0.2", dst="203.0.113.9") /
       TCP(sport=40000, dport=80, flags="S"))
sendp(pkt, iface="lan0p", count=3, inter=0.2, verbose=0)
PY

wait "$cap" 2>/dev/null

python3 - "$PCAP" <<'PY'
import sys
from scapy.all import rdpcap, IP, TCP
try:
    pkts = rdpcap(sys.argv[1])
except Exception:
    print("CAPTURE_NONE")
    sys.exit(0)
ipp = [p for p in pkts if IP in p and TCP in p]
if not ipp:
    print("CAPTURE_NONE")
    sys.exit(0)
p = ipp[0]
print("CAP src=%s dst=%s dport=%s chksum_l3=0x%04x" %
      (p[IP].src, p[IP].dst, p[TCP].dport, p[IP].chksum))
# Recompute checksums to validate the rewrite.
raw = bytes(p[IP])
from scapy.all import IP as IP2
reparsed = IP2(raw)
del reparsed[IP].chksum
del reparsed[TCP].chksum
fixed = IP2(bytes(reparsed))
print("CKSUM ip_ok=%s tcp_ok=%s" %
      (fixed[IP].chksum == p[IP].chksum,
       fixed[TCP].chksum == p[TCP].chksum))
PY
