# Error codes

What you search for at two in the morning with a code on the screen. Codes are stable: they are what tests assert on and what you grep for.

```
error[SC024]: 14:7: zone 'testnet' serves DHCP but no interface in it
              has a static address
  hint: a DHCP server needs an address on the segment it serves
```

`error` is refused — nothing was applied. `warning` is not refused: it is something legal that somebody has been surprised by.

---

## System configuration — `SC0xx`

Emitted by `check system` and `apply system` against `/etc/f/system.yaml`.

### Names and identity

| Code | Meaning | Usual fix |
|---|---|---|
| `SC001` | Duplicate zone name. | |
| `SC002` | Duplicate interface name. | |
| `SC003` | Two interfaces claim the same hardware identity. | One MAC is one port. Check for a copy-paste. |
| `SC004` | Interface has no hardware identity to pin its name to. | Add `mac:` or `path:`. A name with nothing behind it is decided by probe order, and a firewall pointing at the wrong port is a bypass. |
| `SC005` | Interface references an undeclared zone. | Declare it under `zones:`, or fix the spelling. |

### Addressing

| Code | Meaning | Usual fix |
|---|---|---|
| `SC010` | Malformed static address. | It must be CIDR: `10.10.0.1/24`, not `10.10.0.1`. |
| `SC011` | Gateway outside the interface's own subnet. | |
| `SC012` | Overlapping subnets across zones. | Two zones on the same network cannot be separated by a firewall between them. |

### Services

| Code | Meaning | Usual fix |
|---|---|---|
| `SC020` | Service bound to a zone that does not exist. | |
| `SC021` | Zone has services bound but no interfaces. | The service would answer nowhere. Put a port in the zone. |
| `SC022` | DHCP server in a zone that also holds a DHCP client. | The box would be serving addresses on a segment where it is asking for one. Almost always the uplink in the wrong zone. |
| `SC023` | More than one DHCP server bound to one zone. | |
| `SC024` | DHCP zone has no statically addressed interface. | A DHCP server needs a fixed address on the segment it serves. |
| `SC025` | Malformed DHCP range. | `range: 10.10.0.100-10.10.0.200`. |
| `SC026` | DHCP range outside the zone's subnet. | |
| `SC027` | Bad or out-of-subnet reservation. | The reserved address must be inside the serving zone's subnet. |
| `SC028` | More than one DNS forwarder bound to one zone, or a malformed upstream. | |
| `SC045` | *(warning)* DNS rebind protection is on and exempts no domain. | See below — this one has bitten people. |
| `SC046` | *(warning)* `rebind_ok` listed while protection is off, so it exempts nothing. | Remove it, or set `stop_dns_rebind: true`. |

### IPv6

| Code | Meaning | Usual fix |
|---|---|---|
| `SC029` | Zone asks for router advertisements but nothing can send them. | |
| `SC030` | Zone asks for `ipv6: full`, which this build refuses. | The datapath cannot classify an ICMPv6 error as `related`, and v6 routers never fragment — so Packet Too Big cannot get through and large transfers hang with nothing logged. Use `off` or `ra`. See [IPV6_STANCE.md](../IPV6_STANCE.md). |
| `SC031` | Zone asks for RAs but has no prefix to advertise. | Give an interface in the zone an `address6:`. Without it dnsmasq's `enable-ra` generates a config line and sends nothing. |
| `SC032` | IPv6 address on a port whose zone says v6 is off. | A contradiction, refused rather than silently ignored. |

### Time

| Code | Meaning | Usual fix |
|---|---|---|
| `SC040` | Malformed NTP upstream. | |
| `SC041` | More than one NTP server bound to one zone. | |
| `SC042` | NTP server in a zone that also holds a DHCP client. | |
| `SC043` | NTP zone has no statically addressed interface. | |
| `SC044` | *(warning)* Nothing is configured to set the clock. | Every timestamp on the box — conntrack ages, lease times, log lines — is stated in a clock that will never be set. Add an `ntp:` block. |

### `SC045` in detail

```
warning[SC045]: zone 'testnet' discards upstream answers that point
                into private address space, and exempts no domain
  hint: an office's internal names are private-addressed by
        definition, so they will resolve to an empty answer with no
        error. List the internal domains under `rebind_ok:`, or drop
        `stop_dns_rebind`
```

This is the one whose symptom points nowhere near its cause. With `stop_dns_rebind: true`, dnsmasq discards any *upstream* answer pointing into private address space. In an office, internal names — the file server, the git server, the printer — are private-addressed by definition, so every one of them resolves to an empty answer with no error code. The only trace is a `possible DNS-rebind attack detected` line in a journal nobody has a reason to be reading.

The setting is off by default for that reason. If you want it, name the exceptions:

```yaml
services:
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
      stop_dns_rebind: true
      rebind_ok: [corp, internal.example]
```

A note for anyone testing this: dnsmasq's private-address test also covers TEST-NET, so `203.0.113.x` is **not** a valid "public" control.

---

## FWL compiler errors

Emitted by `fwl check`, `fwl compile` and `einheit-f reload firewall`. They are not numbered; they are located and named.

### Structure

| Message | Meaning |
|---|---|
| `rule after default` | `default` is the last line. Anything below it is unreachable. |
| `default admits only allow or drop` | `count` and `log` fall through, and "fall through" is not a meaningful final action. `default redirect to <zone>` and `default masquerade` are refused for the same reason. |
| `duplicate @xdp for zone` | One block per zone. |
| `redirect to <unknown zone>` | The destination is not a declared zone. |
| `Tier 1 and Tier 2 in one block` | A block is a rule list *or* one function. Not both. |

### Fields and guards

| Message | Meaning |
|---|---|
| `pkt.dst_port requires 'pkt.proto == tcp or udp' guard` | A port comparison needs a protocol guard in the same condition. Without it the program would read whatever bytes sit at the port offset of an ICMP packet. The same applies to `pkt.tcp.*` and `pkt.icmp.*`. |
| `ordered comparison rejected` | `<`, `<=`, `>`, `>=` on a value that is a name rather than a number — `conntrack(pkt).state`, `pkt.zone`, an address. |
| `pkt.zone is not supported inside a helper def` | A shared helper is compiled once and called from several zones, so it has no single ingress zone. Put the zone-specific part in the caller. |
| `'chain' is a Tier 1 stage boundary` | `chain` separates rules; a function body is not a rule list. |
| `bool in non-bool context` | There is no truthiness. `if my_u16:` is a type error, not "non-zero". |

### Values

| Message | Meaning |
|---|---|
| `invalid IPv4 octet` | |
| `dnat target port out of range 1-65535` | |
| `rate_limit threshold must be > 0` | |
| `rate_limit per= must be src_ip, dst_ip, src_port, or dst_port` | |
| `rate_limit scope= must be zone or global` | |

### Load-time refusals

These come from the daemon rather than the compiler, and the important property is what they leave running.

| Situation | What happens |
|---|---|
| The policy does not compile | Nothing is loaded. The previous policy keeps running. |
| A pinned map's definition changed, on a **hot reload** | The load is refused and the running policy stays up. The message names the map and both definitions. |
| A pinned map's definition changed, on a **cold start** | The unusable pin is removed and the new bundle loads. A firewall that will not start filters nothing at all, which is the worse failure. |

The asymmetry is deliberate. See [recovery.md](../recovery.md#a-restart-left-pins-behind-in-bpffs).
