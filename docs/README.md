# f — documentation

Two audiences, and they want opposite things. Somebody commissioning a box wants one path with no choices on it. Somebody writing policy at two in the morning wants the exact meaning of one construct and nothing else. Mixing those in one file means the first reader drowns and the second cannot find anything, so they are separate here.

## Start here

| If you are… | Read |
|---|---|
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

- There is no `install.md`. Installing this on a fresh board is not yet a thing you can do by following instructions — see [the gaps](#known-gaps) below — and writing the page before the install exists would be writing fiction.
- Where a how-to says "there is no command for this yet", that is not an omission. It is the finding.

## Known gaps

Recorded here so they are not rediscovered. None of these is a documentation problem; each is a thing that has to be built before its page can honestly exist.

- **No install or package step.** Nothing enumerates the deployable set. `build-aarch64/staging/` is hand-maintained and contains `fd`, `fctl` and `einheit-f-ui` — it is missing `einheit-f`, `f-confd` and `f-sysconf` entirely.
- **`deploy/README.md` tells you to `chown fd:fd`.** There is no `fd` user and the unit runs as root, so those commands fail.
- **`deploy/firstboot/firstboot.sh` is v0.1-era.** No zones, no `system.yaml`, no `f-confd`, no `f-dnsmasq`; it writes `default allow` as the starting policy and calls `einheit-f configure firewall`, which does not exist. This is the least-tested code that matters most: it runs once per device and defines what a new box is.
- **`einheit-f --help` lists no commands** — only global options. The command list exists only inside the interactive shell (`help`). See [reference/cli.md](reference/cli.md#gaps-in-the-command-surface).
- **No verb creates a zone, moves an interface into one, or edits a policy file's contents.** `system.yaml` and `.fw` files are edited with an editor. `edit` opens one; nothing composes one.
- **`log` has no sampling and no message.** `log` writes a fixed record to a ring buffer. `log(msg, sampled=N)` is named in the v0.1 spec as deferred and is still deferred.
- **The FWL v0.4 spec has no §6.5/§6.6.** Multi-def helpers and the pipeline splitter are implemented and tested (`fwl/tests/unit/test_multidef.py`, `test_pipeline.py`) but the spec sections they are numbered after do not exist in this branch.
