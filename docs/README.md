# f — documentation

Two audiences, and they want opposite things. Somebody commissioning a box wants one path with no choices on it. Somebody writing policy at two in the morning wants the exact meaning of one construct and nothing else. Mixing those in one file means the first reader drowns and the second cannot find anything, so they are separate here.

## Start here

| If you are… | Read |
|---|---|
| putting the software on a board | [install.md](install.md) — image or bare Debian, to a box passing traffic |
| putting a box on a bench for the first time | [first-hour.md](first-hour.md) — one path, box to a testnet that browses |
| wondering *why* it is shaped like this | [concepts.md](concepts.md) — ports, interfaces, zones, services, and what the datapath does |
| learning to write policy | [fwl/](fwl/README.md) — a progression from `allow`/`drop` to NAT and helpers |
| trying to do one specific thing | [howto/](howto/) — recipes, in the words you would use to ask for them |
| holding an error code | [reference/error-codes.md](reference/error-codes.md) |
| looking for a command | [reference/cli.md](reference/cli.md) |
| looking for a config key | [reference/system-yaml.md](reference/system-yaml.md) |
| in trouble | [recovery.md](recovery.md) — the ways this has actually gone wrong, and what to do |

## The FWL language

[fwl/](fwl/README.md) is the learning path: eight steps, each one a policy you can paste and run, each building on the last.

The specifications are the reference, and stay the authority on meaning: [FWL_V01_SPEC.md](FWL_V01_SPEC.md), [FWL_V02_SPEC.md](FWL_V02_SPEC.md), [FWL_V04_SPEC.md](FWL_V04_SPEC.md). The learning path links into them rather than restating them; where the two disagree the spec wins and the guide is a bug.

## Other documents

- [IPV6_STANCE.md](IPV6_STANCE.md) — what `off`, `ra` and `full` mean per zone, and why `full` is refused today.
- [PKT_V01_SPEC.md](PKT_V01_SPEC.md), [PKT_V02_SPEC.md](PKT_V02_SPEC.md) — the `.pkt` test-case format the three-oracle harness runs.
- [F_DEVELOPMENT_METHODOLOGY.md](F_DEVELOPMENT_METHODOLOGY.md) — how this codebase is worked on.

## The rule these pages are written under

**Every page is walked on a real box before it ships.** Writing the first handbook found five CLI defects; a deployment rehearsal then found thirteen places where it still contradicted reality. A document that lies costs you the trust you needed at the moment something was actually broken, which is worse than having no document at all.

So a page is filled in when the thing it describes works, and not before. Two consequences you will notice:

- [install.md](install.md) was deliberately unwritten until there was an install. Writing it found five more defects, each named on the page where it still shapes a step — a compiler that could not parse after being installed, a daemon that died at exec on a library from somebody's build tree, a dashboard that flapped sixty-seven times while reporting `activating`, an upgrade that stopped in the middle on `ETXTBSY`, and a provisioning run that severed the SSH session making it. Its one remaining unwalked section says so in place.
- Where a how-to says "there is no command for this yet", that is not an omission. It is the finding.

## Known gaps

Recorded here so they are not rediscovered. None of these is a documentation problem; each is a thing that has to be built before its page can honestly exist.

- **The image build is unwalked.** `deploy/image/build_image.py` reads the same manifest as everything else and pre-flights and verifies around the debootstrap, but there is no aarch64 board on this bench, so its chroot steps have never been run. [install.md](install.md#building-an-image) says so in place.
- **NTP, `gateway:` and `address6:` have no verb.** Zones, ports, addresses, DHCP, DNS and reservations are now all editable from the CLI, and so are the common policy changes — see [reference/cli.md](reference/cli.md). Those three keys are not, so a box that needs a default route on a static port, an advertised v6 prefix, or an NTP server still needs an editor for exactly those lines. Everything else in `system.yaml` and the weekly policy changes do not.
- **`set rule` is a conjunction and nothing more.** It composes `allow`/`drop` guarded by a protocol, a port, a source and a destination, all `and`-ed. An `or`, a rate limit, a helper, a chain, `log`, `count` or a conntrack state needs the language. That is a boundary rather than an unfinished feature: a CLI that could express all of FWL would be FWL with worse syntax.
- **`log` has no sampling and no message.** `log` writes a fixed record to a ring buffer. `log(msg, sampled=N)` is named in the v0.1 spec as deferred and is still deferred.
- **The FWL v0.4 spec has no §6.5/§6.6.** Multi-def helpers and the pipeline splitter are implemented and tested (`fwl/tests/unit/test_multidef.py`, `test_pipeline.py`) but the spec sections they are numbered after do not exist in this branch.
