"""Send one TCP/IPv4 frame with VALID checksums out an interface.

The fwl builder intentionally zeros L4 checksums (the BPF oracle ignores
them), but a real-wire NAT incremental-checksum proof needs a valid
input checksum to verify against. scapy fills both checksums on
serialize. Run inside the sender namespace.

Usage: send_scapy.py <iface> <src> <dst> <sport> <dport> <flags>
"""
import sys
from scapy.all import Ether, IP, TCP, sendp, raw


def main() -> int:
  iface, src, dst, sport, dport, flags = sys.argv[1:7]
  frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / \
      IP(src=src, dst=dst) / \
      TCP(sport=int(sport), dport=int(dport), flags=flags, seq=0)
  # Round-trip so scapy computes and embeds valid IP + TCP checksums.
  frame = Ether(raw(frame))
  sendp(frame, iface=iface, verbose=False)
  print(f"sent {len(raw(frame))} bytes out {iface}: "
        f"{src}:{sport} -> {dst}:{dport} [{flags}]")
  return 0


if __name__ == "__main__":
  sys.exit(main())
