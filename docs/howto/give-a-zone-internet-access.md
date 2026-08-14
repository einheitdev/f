# Give a zone internet access

You have a bench segment with private addresses and an office uplink, and you want the bench to reach the outside while the outside cannot reach the bench.

## What you need first

- Both ports in `system.yaml`, in zones, applied, and `show system` reporting `PRESENT: yes` for both.
- The bench interface with a static address; the uplink usually on DHCP.

## The policy

Write `/etc/f/gateway.fw`, substituting your bench's own gateway address and directed broadcast:

```
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
# 1. Traffic addressed to this box is for this box, and must be
#    delivered locally BEFORE the rewrite below. DHCP by port,
#    because a client with no lease cannot address us.
allow if pkt.proto == udp and pkt.dst_port == 67
allow if pkt.dst_ip == 10.10.0.1

# 2. The bench's own broadcast and multicast stay on the bench.
drop if pkt.dst_ip in 224.0.0.0/4
drop if pkt.dst_ip == 255.255.255.255
drop if pkt.dst_ip == 10.10.0.255

# 3. Everything else goes out hidden behind the uplink address.
masquerade
redirect to wan

@xdp(wan)
# Only answers to conversations the bench started. `related` admits
# the ICMP errors those conversations provoke; without it large
# transfers hang.
allow if conntrack(pkt).state in [established, related]
default drop
```

Load it:

```
$ einheit-f reload firewall
```

## Check it worked

```
$ einheit-f show zones      # both ports attached, and in which XDP mode
$ einheit-f show nat        # translations appear as traffic flows
$ einheit-f show counters   # rule hit counts move
```

From a bench machine, resolve a name and fetch something. Then look at it from this side:

```
$ einheit-f show device 10.10.0.132
```

## If the bench stops getting addresses the moment you load this

That is section 1 of the policy missing or misordered, and it is the single most likely way to get this wrong. `masquerade` and `redirect` are unconditional: without a terminal `allow` above them, a client's DHCP request is translated to the uplink address and broadcast onto the office network, and this box's own DHCP server never sees it. See [fwl/06-nat.md](../fwl/06-nat.md#the-shape-above-is-incomplete-and-this-is-the-important-part-of-the-page).

The symptom is distinctive: stopping the firewall makes DHCP work instantly.

## If small things work and large transfers hang

`related` is missing from the `wan` rule. See [fwl/04-stateful.md](../fwl/04-stateful.md#why--established-is-the-wrong-spelling).

## If nothing crosses at all

Check `show zones` for the `MODE` column. `generic` means the driver would not take a native XDP program and you are on the software slow path — correct, but slow. A port showing `(none)` under `ATTACHED` is not carrying the policy at all.
