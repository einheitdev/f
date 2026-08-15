# `system.yaml` reference

`/etc/f/system.yaml` is the one place the appliance's own network is described. Everything else the box runs — the networkd units, the dnsmasq config, the chrony config, the forwarding sysctl — is generated from it. `deploy/system.yaml.example` is this document as a commented file.

You can edit it directly, and you can edit it with the CLI: `set zone`, `set interface zone`, `set address`, `set dhcp`, `set dns`, `set reservation` and their `no` counterparts change the one line they are about and leave your comments, your ordering and your formatting exactly as they were. Both are the same document; there is no second copy. See [cli.md](cli.md#the-system-configuration) for which keys have a verb and which do not — `services.ntp`, `gateway:` and `address6:` are the three that still need you to open the file.

Validate with `einheit-f check system`; every diagnostic code is in [error-codes.md](error-codes.md).

---

## `zones`

```yaml
zones:
  wan:
    ipv6: off
  testnet:
    ipv6: off
```

A zone is a name. Interfaces join it; services bind to it. Zones may be declared with no body.

| Key | Values | Default | |
|---|---|---|---|
| `ipv6` | `off`, `ra`, `full` | `off` | The zone's stance on IPv6, in **both** directions. |

`off` means an incoming router advertisement does not reach the zone: the ports set `accept_ra=0` and `autoconf=0`, v6 forwarding stays off, and dnsmasq refuses to advertise or answer DHCPv6 there. It is not merely "we send no RAs" — the inbound direction is the one that matters, because a bench device that autoconfigures from an office RA routes around the v4 firewall entirely while every counter keeps climbing.

`ra` means this box is the router on that segment: it advertises a prefix and still accepts nobody else's. It requires an `address6:` on an interface in the zone (`SC031`).

`full` is **refused** (`SC030`). See [IPV6_STANCE.md](../IPV6_STANCE.md).

---

## `interfaces`

```yaml
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    address6: "fd00:10:10::1/64"
    gateway: 10.10.0.254
    zone: testnet
```

The key is the durable name — the label on the case and the name in the policy are the same string.

| Key | Values | |
|---|---|---|
| `mac` | `"52:54:00:aa:bb:01"` | The permanent MAC. One of `mac` or `path` is required (`SC004`). |
| `path` | `"pci-0000:01:00.0"` | Firmware/bus path, for a card with no stable MAC. |
| `address` | CIDR, `dhcp`, or omitted | Omitted means link up with no L3 address — the normal state for a port that only carries filtered traffic. |
| `address6` | CIDR | Only legal in a zone whose stance is `ra` (`SC032`); it is the prefix we advertise. |
| `gateway` | address | Must be inside this interface's own subnet (`SC011`). |
| `zone` | zone name | Exactly one. Omitted means the port is in no zone and carries no zone-bound service. |

An interface is pinned to a hardware identity, never to probe order. That pinning becomes a `.link` unit, which means a newly written name is not in effect on a running box until the rename happens — `show system` reports that as a pending rename rather than as a missing port.

---

## `services`

Every service binds to a **zone**. There is no key in any service block that names an interface; the set of ports a service touches is derived from zone membership every time the config is generated.

### `dhcp`

```yaml
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 12h
      dns_servers: [10.10.0.1]
      reservations:
        - mac: "aa:bb:cc:dd:ee:01"
          address: 10.10.0.50
          hostname: bench1
```

| Key | | |
|---|---|---|
| `zone` | required | The zone must have a statically addressed interface (`SC024`) and must not also hold a DHCP client (`SC022`). |
| `range` | required | `start-end`, inside the zone's subnet (`SC026`). |
| `lease` | `12h` | Duration. |
| `dns_servers` | zone's own address | Servers to advertise to clients. Empty means "advertise this box", which is what you want when the same box forwards DNS. |
| `reservations` | | `mac`, `address`, optional `hostname`. The address must be in the zone's subnet (`SC027`). |

One DHCP server per zone (`SC023`).

### `dns`

```yaml
services:
  dns:
    - zone: testnet
      upstream: [9.9.9.9, 1.1.1.1]
      stop_dns_rebind: false
      rebind_ok: []
```

| Key | Default | |
|---|---|---|
| `zone` | required | One forwarder per zone (`SC028`). |
| `upstream` | system resolver | Empty means inherit whatever the uplink handed us. |
| `stop_dns_rebind` | `false` | Discard upstream answers pointing into private address space. |
| `rebind_ok` | `[]` | Domains exempt from that discard, as `rebind-domain-ok=/<d>/`. |

**`stop_dns_rebind` is off by default and that is a decision, not an oversight.** This box lives inside a company, where internal names are private-addressed by definition. Turning it on makes every one of them return an empty answer with no error code, traceable only to one journal line. Turn it on for a zone that resolves nothing but public names, and name the exceptions in `rebind_ok`. `SC045` warns when it is on with nothing exempted.

### `ntp`

```yaml
services:
  ntp:
    - zone: testnet
      upstream: [pool.ntp.org]
      serve: true
```

| Key | Default | |
|---|---|---|
| `zone` | required | Binds the **server** half only. |
| `upstream` | none | Empty means this box learns the time from nowhere (`SC044`). |
| `serve` | `true` | `false` emits `port 0` — there is no listening socket at all, rather than one that refuses queries. |

The client half has no placement, because a client is outbound and needs none. The server answers only on the addresses derived from its zone, so it cannot answer the uplink.

---

## What gets generated from this

| Artifact | From |
|---|---|
| `/etc/systemd/network/10-f-<iface>.link` | `interfaces[].mac` / `.path` |
| `/etc/systemd/network/10-f-<iface>.network` | `interfaces[].address`, `.gateway`, the zone's `ipv6` |
| `/etc/f/generated/dnsmasq.conf` | `zones`, `interfaces`, `services.dhcp`, `services.dns` |
| `/etc/chrony/f-generated.conf` | `services.ntp` — **not** under `/etc/f/`, because Debian's AppArmor profile confines chronyd to `/etc/chrony/` |
| `/etc/sysctl.d/10-f-ipv6.conf` | the per-zone `ipv6` stance |
| `/etc/systemd/journald.conf.d/10-f.conf` | fixed policy: journal cap, rate limiter disabled |

Each carries a digest of its own body. An edit is reported as drift rather than silently overwritten, and `apply system` removes generated files whose interface has left the model — a leftover `.link` still competes for a MAC, and udev decides that by filename order.
