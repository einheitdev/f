# Pin a board to an address

A board on the bench keeps getting a different address out of the DHCP pool and you want it to keep one.

```
$ einheit-f set reservation 52:54:00:f1:00:aa 10.10.0.55 bench-3
 FIELD      │ VALUE
 action     │ set reservation
 mac        │ 52:54:00:f1:00:aa
 address    │ 10.10.0.55
 zone       │ testnet
 written to │ /etc/f/system.yaml
 state      │ written and live (f-confd)
the client keeps its current address until its lease is renewed
```

The hostname is optional.

## What just happened

The reservation went into `system.yaml`, next to the range it comes out of, with your comments intact. It is the model that was edited, not the generated dnsmasq config — see [concepts.md](../concepts.md#generated-files-and-why-you-never-edit-them).

You did not have to say which zone. The address is matched against the subnets of the zones that serve DHCP; an address matching none, or more than one, is refused with the candidates named.

## It does not take effect immediately

**The client keeps its current address until its lease renews.** Wait out the lease, or bounce the port. Until then:

```
$ einheit-f show device 52:54:00:f1:00:aa
 reservation │ 10.10.0.55 (not in effect yet — the client keeps
             │ 10.10.0.132 until it renews)
```

## If f-confd is not running

The state line reads `written, not yet live` and tells you to run `apply system`. Writing the model and regenerating dnsmasq's config are two different events, and only the first one happened.

## Removing it

```
$ einheit-f no reservation 52:54:00:f1:00:aa
```

Removing one that is not there is an **error**, not a no-op. A MAC typed by hand that matches nothing is something you want to be told about rather than to have quietly succeed.

## Doing it by hand instead

The equivalent edit to `system.yaml`:

```yaml
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 12h
      reservations:
        - mac: "52:54:00:f1:00:aa"
          address: 10.10.0.55
          hostname: bench-3
```

followed by `einheit-f check system` and `einheit-f apply system`. A reservation outside the zone's subnet is refused as `SC027`.
