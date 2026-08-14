# Find out what just appeared on the segment

Somebody plugged something in. You want to know what it is and what it is talking to.

## What is here

```
$ einheit-f show leases
 NEW │ MAC               │ ADDRESS     │ HOSTNAME │ ZONE    │ FIRST SEEN │ LAST SEEN │ EXPIRES
 NEW │ 52:54:00:f1:00:aa │ 10.10.0.132 │ bench-3  │ testnet │        14s │        0s │      2m
     │ aa:bb:cc:dd:ee:02 │ 10.10.0.102 │ (none)   │ testnet │      >=11m │        0s │     11h
     │ aa:bb:cc:dd:ee:01 │ 10.10.0.101 │ board-a  │ testnet │       >=1h │        0s │     11h
```

Most recent arrival first, always, so the thing you just plugged in is row one and you do not have to diff anything by eye.

Two columns carry more than they look like they do.

**`NEW`** means the box *watched this device arrive* — it was absent the last time anything looked, and it is here now. It is never set from a device that was simply already there. A flag that fired for everything on a week-old box would teach you to ignore the column that exists to catch your eye.

**`>=`** in a time column means the same thing from the other side: we did not watch it happen, and this is a bound derived from the lease rather than a measurement. `14s` with no `>=` is a measurement.

A `*` after a MAC means the device has a static reservation.

Variants:

- `show leases new` — only what turned up in the last 15 minutes.
- `show leases all` — includes devices with no current lease; their last known address is still shown.
- `--format json` — machine-readable. Prose goes to stderr in this mode, so `| jq` gets clean JSON and you still see the warnings.

## Watch for the next one

```
$ einheit-f watch show leases
watching `show leases` — no time limit. Ctrl-C to stop.
```

The screen paints immediately, then repaints **only when something changes**, with a banner naming what happened:

```
 ARRIVED
 52:54:00:f1:00:bb
4 device(s) leased  ▁▁▂▃▄
```

A quiet segment stays quiet, so the one line that matters is not buried under a repaint every two seconds. The sparkline is the count of leased devices, one sample per poll.

`watch show leases 5m` bounds it. With no window and a terminal attached it runs until Ctrl-C; run from a script with no tty it stops after 30 seconds, so it cannot hang a pipeline. That makes it usable over SSH as a one-shot:

```
$ ssh box einheit-f watch show leases 5m
```

## What is it talking to

```
$ einheit-f show device 10.10.0.132
 FIELD       │ VALUE
 mac         │ 52:54:00:f1:00:aa
 address     │ 10.10.0.132
 hostname    │ bench-3
 zone        │ testnet
 lease       │ holds a lease, 1m left
 first seen  │ 14s ago
 last seen   │ 0s ago
 reservation │ none — the address may change

 DIR │ PROTO │ PEER           │ LOCAL PORT │ VIA    │ STATE       │ PACKETS │ IDLE
 out │ tcp   │ 1.1.1.1:443    │      40001 │ nat    │ established │       9 │   1s
 out │ tcp   │ 203.0.113.9:80 │      40000 │ nat    │ established │       4 │   1s

 TALKING TO  │ PACKETS │ SHARE
 1.1.1.1     │       9 │ ############## 69%
 203.0.113.9 │       4 │ ###### 31%
```

Takes a MAC in any spelling, an IPv4 address, or a hostname. An ambiguous name is reported as ambiguous with every match listed, never silently resolved to whichever row sorted first.

**Read the `VIA` column.** Behind a masquerade the connection table is keyed on the addresses that are *on the wire* — the gateway's, not the device's — so the device's own flows do not appear under its own address at all. `VIA nat` means the row was found by joining through the NAT table and `LOCAL PORT` is the device's real port. `VIA direct` means conntrack named the device itself.

This is worth knowing because it is also the shape of the wrong answer: a tool that filters the connection table by the device's address finds nothing on a masquerading gateway and cheerfully reports that the board is talking to nobody.

## When the answer is "I could not ask"

```
 FLOWS
 unknown — fd could not be asked
fd is not running (no socket at ipc:///run/f/control.sock). This is not
the same as a device that is talking to nobody: with fd down there is
no connection table to read.
```

versus, when the daemon is up and genuinely has nothing:

```
 FLOWS
 fd is tracking no connections for this device
fd answered. Its conntrack table has no entry for this device's
address, nor for any of the translated endpoints NAT says belong to it.
```

Those two situations look identical on any tool that does not bother to distinguish them, which is why this one does.

## If arrivals are never marked NEW

The device journal is not being written. `show leases` says so at the top:

```
device history is NOT being recorded (cannot write
/var/lib/f/devices.json) — arrivals will not be detected
```

Usually running as a non-root user, or a full filesystem.

There is also a design limit worth knowing: the poller runs *inside a CLI invocation*. `watch show leases` records arrivals while it is running; between sessions the journal only advances when somebody runs `show leases`. A device that arrived and left while nothing was looking was not watched, and is reported as such rather than guessed at.
