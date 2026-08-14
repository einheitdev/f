# Change something without locking yourself out

You are on SSH, about to change an address, a zone, or an interface's pinning. If you get it wrong you lose the session and the box.

## Do this

```
$ einheit-f apply system confirmed 5
applied via f-confd, revision 2

CONFIRM WITHIN 5m — run `confirm system`, or the previous
configuration is restored automatically.
```

Then check you still have the box — that your session works, that the ports came up, that DHCP still answers. If you do:

```
$ einheit-f confirm system
confirmed — the change stays
```

If you do not, **do nothing**. After the window `f-confd` puts the previous configuration back by itself:

```
audit user=confd cmd=auto_revert ok=true
  outcome=commit-confirm expired; reverted to commit 1
```

## Why this works when a shell trick would not

The timer lives in `f-confd`, a long-lived daemon, not in your CLI. A timer in a CLI over SSH dies with the connection it exists to protect — which is the one failure it was supposed to cover.

If you reconnect mid-window, `show system` leads with the countdown, so you find out the clock is running without having to know to ask:

```
CONFIRM PENDING — 59s left on revision 2. Run `confirm system` to keep
this configuration, or wait and the previous one is restored.
```

## If f-confd is not running

The confirmed apply is **refused** rather than applied without a way back:

```
error  no_confd
the revert timer lives in f-confd, which is not running — a confirmed
apply would have nothing to undo it

hint: start it (systemctl start f-confd), or use `apply system` and
      accept that a change which severs your access will not be
      rolled back
```

Start `f-confd` first.

## What the revert does and does not cover

It restores the **system configuration** and the artifacts derived from it. It is not a snapshot of the whole box: a change you made outside `system.yaml` — an `ip addr add` by hand, a hand-edited unit — is not part of the revision and does not come back.

It also does not un-rename a port. If the applied configuration renamed an interface and you rebooted inside the window, you are past the point where the timer helps.

## Check first, always

`check system` validates without applying, and it is instant:

```
$ einheit-f check system
ok — /etc/f/system.yaml
```

Warnings are worth reading rather than skipping. They are things that are legal and that somebody has been surprised by — for example `SC045`, which fires when DNS rebind protection would silently delete every internal name in the building.
