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

## 2. Say what the box is

Everything the box is lives in one file, `/etc/f/system.yaml`, and you can write the whole of it from the CLI. Each command edits that file in place and applies it — including starting the service unit a binding implies, and stopping one nothing binds any more. Nothing is written anywhere else, and there is no second step.

```
$ einheit-f set zone wan
$ einheit-f set zone testnet
$ einheit-f set interface zone enp1s0f0 wan
$ einheit-f set interface zone enp1s0f1 testnet
$ einheit-f set address enp1s0f0 dhcp
$ einheit-f set address enp1s0f1 10.10.0.1/24
$ einheit-f set dhcp testnet 10.10.0.100-10.10.0.200 12h
$ einheit-f set dns testnet 9.9.9.9 1.1.1.1
```

`set interface zone` on a port the configuration has not seen before declares it *and pins it to the MAC the kernel reports for it*, which is why you wrote those down in step 1. The names above are the ones the ports have now; giving them the durable names this page uses — `wan0`, `lan0` — means editing the `interfaces:` keys, which is a rename and is covered in [reference/system-yaml.md](reference/system-yaml.md).

What the commands wrote:

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

You can also write that file by hand — start from `deploy/system.yaml.example`, which is the same shape with every option commented — and the CLI will keep your comments and your ordering when it next edits it. The two are the same document, not two ways of configuring the box.

Read the `services` block again and notice what is not in it: no interface name, anywhere. `set dhcp` takes a zone and has no argument for a port either. Services bind to a zone, so "DHCP answers on the uplink" is not a configuration mistake you can make — at the prompt or in the file. See [concepts.md](concepts.md#zone-to-service-why-the-rogue-dhcp-leak-is-inexpressible).

**Two keys still need the editor**: `gateway:` on a static interface, and `address6:` on a zone that advertises IPv6. There is no verb for either yet, and [reference/cli.md](reference/cli.md#gaps-in-the-command-surface) says so.

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
dhcp answers on: lan0
f-dnsmasq.service: STARTED — it was not running, and systemd now reports it active
```

This generated the dnsmasq config from the model, had dnsmasq validate it, and installed it. The generated files are derived artifacts: digest-stamped, never hand-edited, and an edit to one is reported as drift rather than quietly overwritten.

The last line is the apply owning the service. The units this model implies are enabled and started by the apply that makes it live, and one the model no longer binds anywhere is stopped by the same apply — you do not reach for `systemctl` after a `set dhcp`. What that line reports is read back out of `systemctl show` **after** the action, never taken from the exit code: `systemctl enable --now` exits 0 for a unit that started, crashed and entered auto-restart. If the service will not run, this command is an **error** rather than a success with a note, because a configuration on disk that nothing is serving is not an applied configuration.

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

The policy is a second document, `/etc/f/rules.fw`. Its shape — which zone gets which block, and in what order the statements go — is the thing worth understanding, so write it once:

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

## 8. Change it without opening it again

From here the policy is *evolved*, and the everyday changes have verbs. Look at it first — the numbers are what the removal verb takes, and they restart in each block:

```
$ einheit-f show policy wan
zone wan  (/etc/f/rules.fw)
 # │ STATEMENT                                               │ MATCHES
 1 │ allow if conntrack(pkt).state in [established, related] │ when it matches
 2 │ default drop                                            │ every packet — stops here

this is the policy source on disk; `show zones` reports what fd
has loaded and attached
```

Read the `MATCHES` column. `default drop` acts on every packet that reaches it and stops there, so nothing written below it can ever match — which is why you do not choose where a new rule goes:

```
$ einheit-f set rule wan allow tcp 22
 zone      │ wan
 action    │ add rule
 statement │ allow if pkt.proto == tcp and pkt.dst_port == 22
 position  │ 2 in the block, line 12
 before    │ default drop
 why there │ that statement is unconditional — anything after it can never match
 saved to  │ /etc/f/rules.fw
 running   │ yes — fd reloaded
```

(On a console narrower than about a hundred columns the `MATCHES` column is dropped and the statement text kept. The warning is still there: an unconditional statement is highlighted in the `STATEMENT` column itself.)

The policy was compiled before it was written and reloaded after: one that does not compile never replaces one that does, and if `fd` refuses the reload you are told the file changed and the running policy did not.

Opening a port inwards is a pair of statements, and it is one command because getting them out of step is the classic way to leak untranslated frames into the bench:

```
$ einheit-f set forward wan tcp 80 10.10.0.20:8080
```

You did not name the inside zone. The model already knows which segment `10.10.0.20` is on.

To take something back out, name the position:

```
$ einheit-f no rule wan 2
$ einheit-f no forward wan tcp 80
```

`show policy` reads the file. `show zones` reads what `fd` has actually loaded and attached — different questions, and the reason they are different commands.

## 9. Look at what is happening

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
