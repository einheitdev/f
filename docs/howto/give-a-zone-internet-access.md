# Give a zone internet access

You have a bench segment with private addresses and an office uplink, and you want the bench to reach the outside while the outside cannot reach the bench.

## What you need first

Both ports in zones, addressed, applied, and `show system` reporting `PRESENT: yes` for both. From nothing, that is:

```
$ einheit-f set zone wan
$ einheit-f set zone lan
$ einheit-f set interface zone wan0 wan
$ einheit-f set interface zone lan0 lan
$ einheit-f set address wan0 dhcp
$ einheit-f set address lan0 10.10.0.1/24
$ einheit-f show system
```

Each of those edits `/etc/f/system.yaml` and applies it. `set interface zone` on a port that is not declared yet declares it and pins it to the MAC the kernel reports, so the name survives a reboot that renumbers the bus.

## The policy

Write it to **`/etc/f/rules.fw`**, substituting your bench's own gateway address and directed broadcast. That path is not a suggestion: `reload firewall` compiles the CLI's `--source`, which defaults to `/etc/f/rules.fw`, and fd's own watcher reads `watch.source` in `/etc/f/fd.yaml`, which is the same file. A policy written under any other name is a file nothing compiles — and `reload firewall` will answer success, for having reloaded the policy that was already running. If you want it somewhere else, change both of those settings and not just one.

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

`fd` compiles and attaches on the thread that answers this command, so on a slow box or with a large policy it will not reply until it has finished. If you get `no answer in 180s`, that is not "fd is broken" and it is not "nothing happened": run `show policy`, which reports what fd has in the packet path beside the file on disk, before you do anything else — and in particular before `rollback`.

After that, the everyday changes have verbs — `einheit-f show policy lan` numbers the statements, `set rule` adds one where it can still match, `no rule` takes one out. See [reference/cli.md](../reference/cli.md#the-policy). The whole-file version above is what you write once, because the *ordering* below is the part that has to be deliberate.

## The services are already on

`set dhcp` and `set dns` enable and start the unit that serves them, as part of the same apply that writes the model — and the line they print afterwards is what `systemctl show` said, not what `systemctl enable --now` returned:

```
$ einheit-f set dhcp lan 10.10.1.100-10.10.1.150 12h
 zone     │ lan
 applied  │ yes
 service  │ f-dnsmasq.service: STARTED — it was not running, and systemd now reports it active
```

If the unit will not start, that is an **error**, not a footnote on a success: the configuration is on disk and nothing is serving it, and the command says so with systemd's own reason. `journalctl -u f-dnsmasq` is the next step, and re-running the verb is not — the edit already took.

The other direction is the same apply: `no dhcp` on the last binding stops and disables the unit, so the box is not still answering DHCP after you told it not to.

Either way, the screen that reads the kernel rather than the model is:

```
$ einheit-f show services   # ANSWERS ON should name the zone's port
```

`BOUND TO` is what the model asks for; `ANSWERS ON` is what the daemon's sockets actually say. A service that is `running` and answering on nothing is a real state and this is where it shows.

## Check it worked

```
$ einheit-f show zones      # both ports attached, and in which XDP mode
$ einheit-f show nat        # translations appear as traffic flows
$ einheit-f show conntrack  # flows appear as the bench opens them
$ einheit-f show counters   # what each `count <name>` in the policy has counted
```

`show counters` reads the map the datapath writes and prints each slot under the name your policy gave it. A zone that declares no `count` says so, and a zone whose counters cannot be read says *that* rather than showing zeros — see [5. Observability](../fwl/05-observability.md).

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

Check `show status` for the `forwarding` row before anything else. This box **fails closed** — it routes only while it is filtering — so `OFF` there means nothing of yours is in the packet path, and that is the fault to chase rather than the sysctl. The row names its own reason, and [recovery.md](../recovery.md#nothing-crosses-the-box-and-show-zones-looks-fine) reads all four of them. Setting `net.ipv4.ip_forward` by hand fixes nothing: `fd` put it where it is.

If forwarding is `on`, check `show zones` for the `MODE` column. `generic` means the driver would not take a native XDP program and you are on the software slow path — correct, but slow. A port showing `(none)` under `ATTACHED` is not carrying the policy at all.
