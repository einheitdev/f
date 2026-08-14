#!/usr/bin/env python3
"""A minimal DHCP client, for asserting what a testnet client gets.

The rig carries no dhclient/udhcpc/dhcpcd, and the appliance's headline
workflow is "plug a board in and watch it take an address". A test that
cannot make a DHCP client is a test that has to trust the lease file,
which is the server's own account of what it did.

Two questions, and they need opposite exit codes:

  * `--expect lease` — a client on this segment MUST get an address.
  * `--expect silence` — nothing may answer here. This is the uplink
    hard gate: proving a DHCP server does NOT speak on a port is not
    the same assertion as proving it speaks on another, and only a
    real DISCOVER on the wire can answer it.

Prints one JSON object either way, so a caller can assert on fields
rather than on scraped text.
"""
import argparse
import json
import random
import sys
import time

from scapy.all import (  # noqa: E402  (vendored path set by caller)
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    conf,
    get_if_hwaddr,
    srp1,
)

# DHCP option name -> the key we report it under. Anything not named
# here is still reported, under its own option name, so a server that
# sends something unexpected is visible rather than filtered out.
_INTERESTING = {
    'router': 'router',
    'name_server': 'dns',
    'lease_time': 'lease_s',
    'server_id': 'server_id',
    'subnet_mask': 'netmask',
    'domain': 'domain',
}


def _options(pkt):
  """Flatten a BOOTP packet's DHCP options into a dict."""
  out = {}
  for opt in pkt[DHCP].options:
    if not isinstance(opt, tuple):
      continue
    name, *rest = opt
    value = rest[0] if len(rest) == 1 else list(rest)
    if isinstance(value, bytes):
      try:
        value = value.decode('utf-8', 'replace')
      except Exception:
        value = repr(value)
    out[_INTERESTING.get(name, name)] = value
  return out


def _exchange(iface, mac, xid, msg_type, ciaddr=None, extra=None,
              timeout=5.0):
  """Send one DHCP message and return the single reply, or None."""
  chaddr = bytes.fromhex(mac.replace(':', ''))
  options = [('message-type', msg_type)]
  options.extend(extra or [])
  options.append('end')
  pkt = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
         IP(src='0.0.0.0', dst='255.255.255.255') /
         UDP(sport=68, dport=67) /
         BOOTP(chaddr=chaddr, xid=xid, flags=0x8000) /
         DHCP(options=options))
  if ciaddr:
    pkt[BOOTP].ciaddr = ciaddr
  return srp1(pkt, iface=iface, timeout=timeout, verbose=0)


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument('iface')
  ap.add_argument('--expect', choices=['lease', 'silence'],
                  default='lease')
  ap.add_argument('--timeout', type=float, default=5.0)
  ap.add_argument('--hostname', default=None)
  args = ap.parse_args()

  conf.checkIPaddr = False
  mac = get_if_hwaddr(args.iface)
  xid = random.randint(1, 0xFFFFFFFF)
  extra = []
  if args.hostname:
    extra.append(('hostname', args.hostname.encode()))

  result = {
      'iface': args.iface,
      'mac': mac,
      'expect': args.expect,
      'offered': False,
      'acked': False,
  }

  started = time.time()
  offer = _exchange(args.iface, mac, xid, 'discover', extra=extra,
                    timeout=args.timeout)
  result['discover_wait_s'] = round(time.time() - started, 2)

  if offer is None:
    # No OFFER. For the silence assertion this is the pass; the
    # caller decides, not us.
    result['reason'] = 'no OFFER within timeout'
    print(json.dumps(result))
    return 0 if args.expect == 'silence' else 1

  result['offered'] = True
  result['address'] = offer[BOOTP].yiaddr
  result.update(_options(offer))
  server_id = result.get('server_id')

  req_extra = list(extra)
  req_extra.append(('requested_addr', offer[BOOTP].yiaddr))
  if server_id:
    req_extra.append(('server_id', server_id))
  ack = _exchange(args.iface, mac, xid, 'request', extra=req_extra,
                  timeout=args.timeout)
  if ack is not None and _options(ack).get('message-type') != 6:
    result['acked'] = True
    result['address'] = ack[BOOTP].yiaddr
    result.update(_options(ack))

  print(json.dumps(result))
  if args.expect == 'silence':
    # Something answered where nothing should. That is the finding.
    return 1
  return 0 if result['acked'] else 1


if __name__ == '__main__':
  sys.exit(main())
