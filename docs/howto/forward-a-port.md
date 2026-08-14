# Forward a port to a machine inside

Something on the office side needs to reach a service on a bench machine — a web UI on a test rig, a build agent, an instrument's control port.

## The policy

Two rules, not one. `dnat` rewrites the destination and **falls through**; `redirect` is what actually emits the frame into the other zone.

```
zone wan = [wan0]
zone lan = [lan0]

@xdp(wan)
# Office TCP/80 on our uplink address lands on the rig's 8080.
dnat to 10.10.0.20:8080 if pkt.proto == tcp and pkt.dst_port == 80
redirect to lan if pkt.proto == tcp and pkt.dst_port == 80

# Everything else from the office: only answers to conversations the
# bench started.
allow if conntrack(pkt).state in [established, related]
default drop

@xdp(lan)
allow if pkt.proto == udp and pkt.dst_port == 67
allow if pkt.dst_ip == 10.10.0.1
masquerade
redirect to wan
```

The `redirect` rule tests `pkt.dst_port == 80`, the **original** port, even though the line above rewrote it. Conditions after a NAT rewrite read the pre-translation fields; the emitter captures them before any rewrite happens.

The return path needs no rule at all. The reply mapping installed by the `dnat` restores the original public destination before any of the `wan` block's rules run.

## Check it

```
$ einheit-f show nat
 PROTO │ TYPE │ ORIG SRC        │ ORIG DST         │ TRANSLATED
 tcp   │ dnat │ 10.1.4.7:51501  │ 198.51.100.9:80  │ 10.10.0.20:8080
```

From the office side, connect. From this side, watch the translation appear.

## Before you rely on it

- **IPv4 only.** A v6 frame is never rewritten.
- **The port range is 1–65535**; anything else is a compile error.
- **The NAT map is finite and shared.** Both directions of translation live in it. See [recovery.md](../recovery.md#nat-stops-working-for-new-flows).
- **This punches a hole through the stateful rule above it.** The `dnat`/`redirect` pair sits *before* the conntrack rule, so office-initiated traffic on that port reaches the bench machine whether or not anything asked for it. That is what a port forward is; be deliberate about which port and, where you can, which source:

```
dnat to 10.10.0.20:8080 if pkt.proto == tcp and pkt.dst_port == 80
       and pkt.src_ip in 10.1.0.0/16
redirect to lan if pkt.proto == tcp and pkt.dst_port == 80
       and pkt.src_ip in 10.1.0.0/16
```

Both rules need the same guard. A `dnat` whose guard is narrower than its `redirect` sends untranslated frames into the bench zone.
