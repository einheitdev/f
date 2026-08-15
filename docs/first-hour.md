# The first hour

One path from a box on a bench to a testnet that gets addresses and reaches the internet. No alternatives and no options: if you need this page you cannot yet make those choices, and the point is to reach something working that you can then take apart.

This assumes the software is already on the box and provisioned. Getting it there is [install.md](install.md); if firstboot ran with a provisioning file, most of what follows has already happened and this page is how to check it and take it apart.

Two ports, and this page calls them what they are for the rest of their lives:

- **`wan0`** — the office uplink. Nothing is bound to it. That is the point of it.
- **`lan0`** — the test bench. This is where the services live.

---

## 1. Find out what you actually have

```
$ ip -o link
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: enp1s0f0: <BROADCAST,MULTICAST,UP> ... link/ether 52:54:00:aa:bb:01
3: enp1s0f1: <BROADCAST,MULTICAST,UP> ... link/ether 52:54:00:aa:bb:02
```

Write down the two MAC addresses and which physical socket each one is. Label the case now; you will not remember in a month, and the label and the config are supposed to be the same string.

## 2. Write the configuration

Everything is one file, `/etc/f/system.yaml`. Start from `deploy/system.yaml.example`, which is the same shape with every option commented.

```yaml
zones:
  wan:
  testnet:

interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet

services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 12h
  dns:
    - zone: testnet
      upstream: [9.9.9.9, 1.1.1.1]
```

Read the `services` block again and notice what is not in it: no interface name, anywhere. Services bind to a zone, so "DHCP answers on the uplink" is not a configuration mistake you can make. See [concepts.md](concepts.md#zone-to-service-why-the-rogue-dhcp-leak-is-inexpressible).

## 3. Check it before you apply it

```
$ einheit-f check system
ok — /etc/f/system.yaml
```

Errors are named, located and refused. Warnings are named and not refused: they are things that are legal and worth knowing you asked for. Every code is in [reference/error-codes.md](reference/error-codes.md).

## 4. Apply it

```
$ einheit-f apply system
applied via f-confd, revision 1
wrote /etc/systemd/network/10-f-wan0.link
wrote /etc/systemd/network/10-f-wan0.network
wrote /etc/systemd/network/10-f-lan0.link
wrote /etc/systemd/network/10-f-lan0.network
wrote /etc/f/generated/dnsmasq.conf
applied without a confirm window — use `apply system confirmed
<minutes>` when the change could cut your own access
```

This generated the dnsmasq config from the model, had dnsmasq validate it, and installed it. The generated files are derived artifacts: digest-stamped, never hand-edited, and an edit to one is reported as drift rather than quietly overwritten.

**If the output ends with a `PENDING RENAME` block, stop and read it.** It means the ports named in that configuration do not exist under those names yet, so nothing you just wrote is in effect. The block gives you the three commands that apply the rename, and [recovery.md](recovery.md#a-configuration-was-applied-but-the-ports-it-names-do-not-exist-yet) explains why it happens. A reboot also works.

## 5. Confirm the box agrees with you

```
$ einheit-f show system
 ZONE    │ INTERFACES │ SERVICES │ IPV6
 wan     │ wan0       │ -        │ off
 testnet │ lan0       │ dhcp+dns │ off

 INTERFACE │ PINNED TO         │ ADDRESS      │ ZONE    │ PRESENT
 wan0      │ 52:54:00:aa:bb:01 │ dhcp         │ wan     │ yes
 lan0      │ 52:54:00:aa:bb:02 │ 10.10.0.1/24 │ testnet │ yes

 DERIVED            │ INTERFACES
 services listen on │ lan0
 dhcp answers on    │ lan0
 excluded           │ wan0
```

Two rows earn their place here.

**`PRESENT`** answers "is the port in the `PINNED TO` column plugged into this box right now". It matches on the hardware identity, not on the name — the name is the thing that has not happened yet when a rename is pending. Anything other than `yes` is explained underneath the table.

**`excluded`** is the containment said out loud: the uplink is named as a port DHCP will not answer on, rather than merely being left out of a list.

```
$ einheit-f show services
 SERVICE            │ STATE   │ ZONES   │ BOUND TO │ ANSWERS ON │ UNIT
 dhcp+dns (dnsmasq) │ running │ testnet │ lan0     │ lan0       │ f-dnsmasq.service
```

`BOUND TO` is what you asked for. `ANSWERS ON` is read out of the kernel's socket table — where the daemon actually is. They are two columns because the whole reason this view exists is the case where they disagree, and a column computed from the config cannot disagree with the config.

## 6. Plug a board in

```
$ einheit-f show leases
 NEW │ MAC               │ ADDRESS     │ HOSTNAME │ ZONE    │ FIRST SEEN │ LAST SEEN │ EXPIRES
 NEW │ 52:54:00:f1:00:aa │ 10.10.0.132 │ bench-3  │ testnet │        14s │        0s │        11h
```

Most recent arrival first, always: the board you just plugged in is row one and you do not have to diff anything by eye. `NEW` means the box *watched it arrive*, not that it noticed it was there.

At this point the bench has addresses and can resolve names. It cannot yet reach anything, because no policy is loaded and nothing is forwarding.

## 7. Give the bench a way out

Write `/etc/f/testnet.fw`:

```
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
# Anything addressed to this box is for this box. These two lines are
# not optional on a gateway that also runs DHCP and DNS: `masquerade`
# and `redirect` are unconditional, so without them a client's DHCP
# request is translated and sent out of the uplink.
allow if pkt.proto == udp and pkt.dst_port == 67
allow if pkt.dst_ip == 10.10.0.1
masquerade
redirect to wan

@xdp(wan)
# Only answers to conversations the bench started. `related` admits the
# ICMP errors those conversations provoke — without it, ping and DNS
# work and every large transfer hangs.
allow if conntrack(pkt).state in [established, related]
default drop
```

Load it:

```
$ einheit-f reload firewall
```

The bench can now reach the internet, hidden behind the uplink address, and nothing on the office side can start a conversation with it.

If you want to understand what you just pasted rather than only run it, that policy is the destination of [the FWL guide](fwl/README.md), and its steps build up to exactly this shape.

## 8. Look at what is happening

```
$ einheit-f show zones          # which ports are attached, and in what XDP mode
$ einheit-f show nat            # active translations, and the masquerade source
$ einheit-f show conntrack      # the connection table
$ einheit-f show device 10.10.0.132
```

`show device` is the one to remember. It joins the lease, the device journal and the connection table, and it answers "what is this thing talking to" for a device *behind* the masquerade — which is exactly the question a tool that filters conntrack by the device's address gets wrong, because behind NAT that address is not on the wire.

---

## Where to go next

- Change something without locking yourself out: [howto/change-something-safely.md](howto/change-something-safely.md).
- Understand why it is shaped like this: [concepts.md](concepts.md).
- Write your own policy properly: [fwl/](fwl/README.md).
- When it breaks: [recovery.md](recovery.md).
