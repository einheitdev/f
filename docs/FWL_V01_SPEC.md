# FWL v0.1 — Language Specification

## What FWL Is

FWL is a small declarative language for writing firewall rules. A `.fw` file declares a sequence of rules. Each rule says "if this packet matches these conditions, take this action." The compiler turns the file into an XDP/eBPF program that runs at line rate in the kernel.

This document specifies FWL v0.1. It is the smallest viable surface — enough language to write a useful firewall, not enough to overwhelm the implementation. Future versions extend it; v0.1 is frozen at what's described here.

## Hello World

Drop all incoming traffic from a specific subnet. Allow everything else.

```python
@xdp(eth0)

drop if pkt.src_ip in 10.0.0.0/24
allow
```

That's a complete v0.1 program. Three lines including the hook declaration. The compiler emits a BPF program that attaches to `eth0`, evaluates each packet against the rules in order, and returns `XDP_DROP` or `XDP_PASS`.

## Lexical Structure

### Whitespace and Comments

Whitespace is significant only as a token separator. No indentation rules; programs are flat sequences of rules. Blank lines allowed.

Comments start with `#` and run to end of line. No multi-line comments in v0.1.

```python
# This is a comment. Single line, starts with #.
allow if pkt.proto == tcp  # comment after a statement
```

Comments and whitespace are stripped before parsing. The grammar below operates on the post-stripping token stream.

### Identifiers

Identifiers match `[a-z_][a-z0-9_]*` — lowercase letters, digits (not in first position), and underscores. They appear as: built-in names (`rate_limit`, `tcp`, `udp`, `icmp`), field accessor segments (`pkt`, `proto`, `src_ip`, etc.), interface names in `@xdp(...)`, and counter names in `count <n>`. v0.1 has no user-defined identifiers in the sense of variables, function definitions, or labels.

### Literals

| Kind | Syntax | Example |
|---|---|---|
| Decimal integer | `[0-9]+` | `80`, `443`, `65535` |
| Hex integer | `0x[0-9a-fA-F]+` | `0xff`, `0x1A` |
| IPv4 address | dotted quad, decimal octets | `192.168.0.1` |
| IPv4 CIDR | dotted quad + `/` + prefix | `10.0.0.0/24`, `0.0.0.0/0` |
| Port range | `lo..hi` | `1000..2000` |
| List | `[ items, ... ]` | `[80, 443, 8080]` |

IPv4 octets are decimal only; hex octets (`0xC0.0xA8.0.1`) are not in v0.1. Strings, floats, booleans-as-literals: not in v0.1.

## Program Structure

A v0.1 program has exactly one hook declaration followed by a sequence of rules.

```python
@xdp(<interface>)

<rule>
<rule>
...
```

Hook declaration is required and appears exactly once at the top of the file. The interface name is a bare identifier matching a real network interface on the host (`eth0`, `eno1`, `wlp3s0`, etc.). The compiler does not validate that the interface exists — that happens at load time.

Rules execute top to bottom. The first rule whose condition matches determines the action. If no rule matches, the default action is `allow`.

### Rule Syntax

```
<action> [if <condition>] [<modifier>]
```

- `<action>` — `allow`, `drop`, `log`, or `count <n>`. Required.
- `if <condition>` — Boolean expression. Optional; if absent, the rule unconditionally applies.
- `<modifier>` — currently only `limited by rate_limit(...)`. Optional.

Examples:

```python
allow                                            # unconditional
drop if pkt.proto == icmp                        # conditional
allow if pkt.proto == tcp and pkt.dst_port == 22
       limited by rate_limit(10, per=src_ip)
log if pkt.src_ip in 192.168.0.0/16
count web_traffic if pkt.proto == tcp and pkt.dst_port in [80, 443]
```

A rule with `log` or `count <n>` action records the event but does not affect packet disposition; evaluation continues to the next rule. `allow` and `drop` are terminal — once a packet matches, evaluation stops and the action takes effect.

`count <n>` increments the named counter. The counter name is a bare identifier (`[a-z_][a-z0-9_]*`) declared by first use; the compiler allocates a slot in a per-CPU counters array map. Userspace tools read the counter values; the BPF program only writes them.

Action behavior at the BPF level:

| Action | XDP return | Counter | Log |
|---|---|---|---|
| `allow` | `XDP_PASS` | none | none |
| `drop` | `XDP_DROP` | none | none |
| `log` | (continues) | none | event to ring buffer |
| `count <n>` | (continues) | named counter +=1 | none |

Default action when no rule matches: `allow` (`XDP_PASS`). Programs may also declare an explicit default rule, which behaves like a final unconditional rule but communicates intent more clearly:

```python
@xdp(eth0)

allow if pkt.dst_port in [80, 443]
default drop                # explicit deny-all default
```

`default <action>` is syntactic sugar for an unconditional rule at the end of the program. The compiler rejects any rule following a `default` rule. Only `allow` and `drop` are valid as default actions — `log` and `count <n>` are non-terminal (they fall through to subsequent rules), and "fall through to subsequent rules" makes no sense as the program's final action.

If no rule and no explicit `default` matches, the implicit default is `allow`.

## The pkt Object

`pkt` is the implicit current-packet variable. It's not a runtime object; it's a compile-time symbol that the compiler tracks to determine which protocol layers need parsing. Touching `pkt.dst_port` causes the compiler to emit Ethernet + IPv4 + L4 parse code with bounds checks. Touching only `pkt.src_ip` causes the compiler to emit Ethernet + IPv4 only.

### v0.1 pkt fields

```
pkt.proto                # L4 protocol enum
pkt.src_ip               # IPv4 source address
pkt.dst_ip               # IPv4 destination address
pkt.src_port             # L4 source port (TCP/UDP only)
pkt.dst_port             # L4 destination port (TCP/UDP only)
pkt.tcp.syn              # TCP SYN flag (TCP only)
pkt.tcp.ack              # TCP ACK flag (TCP only)
```

Nothing else. No `pkt.tcp.fin`, no `pkt.tcp.rst`, no IP options, no ICMP fields, no IPv6, no payload access. Deferred to v0.2+.

### Field types

| Field | Type | Range |
|---|---|---|
| `pkt.proto` | enum | `tcp`, `udp`, `icmp` |
| `pkt.src_ip`, `pkt.dst_ip` | ipv4 | any 32-bit address |
| `pkt.src_port`, `pkt.dst_port` | u16 | 0..65535 |
| `pkt.tcp.syn`, `pkt.tcp.ack` | bool | flag bit |

`tcp`, `udp`, `icmp` are reserved keywords representing protocol enum values. They appear bare (without quotes), only on the right side of `pkt.proto` comparisons.

Boolean fields appear directly as conditions; v0.1 has no boolean literals (`true`, `false`), so write `pkt.tcp.syn` to test whether the SYN flag is set, and `not pkt.tcp.syn` to test whether it is clear. Comparisons like `pkt.tcp.syn == true` are not valid in v0.1 because `true` is not a literal.

### Protocol Guards

Some `pkt` fields are only meaningful for certain protocols. Accessing them outside the appropriate protocol context is a compile-time error.

- `pkt.src_port`, `pkt.dst_port` require `pkt.proto == tcp` or `pkt.proto == udp` to be true on the path to the access.
- `pkt.tcp.syn`, `pkt.tcp.ack` require `pkt.proto == tcp` to be true on the path.

The compiler analyzes each rule's condition to determine which guards are active. A condition like `pkt.proto == tcp and pkt.dst_port == 22` is well-formed; the `tcp` clause must precede the `dst_port` access in `and` order, and the compiler short-circuits evaluation so non-TCP packets exit before reading the port.

Examples that compile:

```python
allow if pkt.proto == tcp and pkt.dst_port == 80
allow if pkt.proto == udp and pkt.dst_port == 53
drop  if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
```

Examples that fail to compile:

```python
# error: pkt.dst_port requires pkt.proto == tcp or udp guard
allow if pkt.dst_port == 80

# error: pkt.tcp.syn requires pkt.proto == tcp guard
drop if pkt.tcp.syn

# error: pkt.tcp.syn requires pkt.proto == tcp guard
#        (pkt.proto == udp does not satisfy the requirement)
drop if pkt.proto == udp and pkt.tcp.syn
```

The constraint-set rule is union-of-branches across `or`. So
`(pkt.proto == tcp or pkt.proto == udp) and pkt.dst_port == 443`
is well-formed: each `or` branch contributes a guard, the union
satisfies `tcp|udp`, and `dst_port` access is allowed.

By precedence (`and` binds tighter than `or`),
`pkt.proto == tcp or pkt.proto == udp and pkt.dst_port == 443`
parses as `tcp or (udp and dst_port == 443)`. The `dst_port` access
sits inside the second branch, where the AND already establishes a
`udp` guard — the constraint-set rule allows it. (If a reader
expected the access to apply to both branches, parens make that
intent explicit.)

### Bounds Checks and Truncated Packets

For every `pkt` field access, the compiler emits a bounds check before the read. If the packet is too short to contain the field, the rule does not match — evaluation falls through to the next rule.

Example: a rule reading `pkt.dst_port` on a packet whose IP header claims TCP but is truncated before the TCP header. The bounds check fails, the rule does not match, the compiler proceeds to the next rule. If no rule matches, the default `XDP_PASS` applies.

Truncated packets do not cause crashes, panics, or undefined behavior. They simply don't match rules that require fields they don't contain.

### IPv4 Specifics

IPv4 packets with options (IHL > 5) are handled correctly. The L4 offset is computed as `ihl * 4` rather than assumed to be 20. Bounds checks use the computed offset.

IP fragmentation: a fragment that does not contain the L4 header (offset > 0) cannot match rules referencing L4 fields. It can match rules that only reference IPv4 fields (`pkt.src_ip`, `pkt.dst_ip`, `pkt.proto`).

The "don't fragment" and "more fragments" flags are not exposed in v0.1.

## Operators

### Comparison

| Operator | Meaning | Operand types |
|---|---|---|
| `==` | equal | any field, with same-type literal |
| `!=` | not equal | any field, with same-type literal |
| `>`, `<`, `>=`, `<=` | ordered comparison | numeric fields with integer literals |
| `in` | set or range membership | see below |

Comparisons return bool. Comparing fields of different types is a compile-time error.

```python
allow if pkt.dst_port == 80                    # u16 == int
allow if pkt.src_ip == 192.168.1.1             # ipv4 == ipv4 literal
drop  if pkt.dst_port > 49152                  # ephemeral range
drop  if pkt.proto == tcp                      # enum == enum keyword
```

### Set and Range Membership (`in`)

```python
# Port list
allow if pkt.proto == tcp and pkt.dst_port in [80, 443, 8080]

# Port range (inclusive on both ends)
allow if pkt.proto == tcp and pkt.dst_port in 1024..65535

# IPv4 CIDR
drop if pkt.src_ip in 10.0.0.0/8
drop if pkt.dst_ip in 192.168.0.0/16

# CIDR list
drop if pkt.src_ip in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
```

The right operand of `in` must be a list of values, a range, a CIDR, or a list of CIDRs. The element type must match the field type.

`in [80]` and `== 80` are equivalent. The compiler may optimize either to the same BPF code; the language treats them as semantically identical.

### Boolean Composition

| Operator | Precedence (lowest to highest) |
|---|---|
| `or` | 1 |
| `and` | 2 |
| `not` | 3 |
| parentheses | overrides |

```python
# Without parens: 'and' binds tighter than 'or'
allow if pkt.proto == tcp and pkt.dst_port == 22
       or pkt.proto == udp and pkt.dst_port == 53
# This parses as:
#   (pkt.proto == tcp and pkt.dst_port == 22)
#   or
#   (pkt.proto == udp and pkt.dst_port == 53)

# Use parens for clarity or to override precedence
drop if not (pkt.src_ip in 10.0.0.0/8 or pkt.src_ip in 192.168.0.0/16)
```

The compiler short-circuits boolean evaluation, both for performance and for protocol guards. `pkt.proto == tcp and pkt.dst_port == 22` will not attempt to read `dst_port` for non-TCP packets.

## The rate_limit Modifier

v0.1 has exactly one stateful primitive: `rate_limit`. It applies to a rule via the `limited by` clause.

### Syntax

```
<rule> limited by rate_limit(<N>, per=<field>)
```

- `<N>` — positive integer, the rate limit threshold (events per second).
- `<field>` — one of `src_ip`, `dst_ip`, `src_port`, `dst_port`. The dimension to bucket by.

### Semantics

The rule's action takes effect only when the rate of matching packets, bucketed by the `per` field's current value, has reached `<N>` per second within the current one-second window. Every matching packet increments the bucket counter, but the action only fires once the bucket has accumulated `<N>` matches.

- If a packet matches the rule's condition: the rate counter for its bucket is incremented.
- If the post-increment count is BELOW the threshold: the rule does not apply this packet. Evaluation continues to the next rule.
- If the post-increment count is AT OR ABOVE the threshold: the action applies (the rule is "active") for this packet.

In `drop limited by rate_limit(N)` form: the first `N` matching packets per bucket per second are NOT dropped by this rule; the (N+1)-th and beyond ARE dropped. This matches the user-facing reading of "drop traffic that exceeds N per second".

Implementation: the compiler emits a per-CPU hash map keyed by the `per` field. Each entry is a sliding-window counter. Token-bucket-style behavior with one-second window granularity.

### Examples

SSH SYN flood protection:

```python
@xdp(eth0)

# Drop new SSH connections beyond 10 per second per source IP
drop if pkt.proto == tcp 
       and pkt.dst_port == 22
       and pkt.tcp.syn and not pkt.tcp.ack
       limited by rate_limit(10, per=src_ip)

allow if pkt.proto == tcp and pkt.dst_port == 22
allow
```

Reading: the first rule matches new SSH connection attempts (TCP SYN without ACK to port 22). The `limited by rate_limit(10, per=src_ip)` clause means: this drop rule only fires for the 11th, 12th, 13th... packet from a given source IP within a one-second window. The first 10 SYNs from each IP are not dropped by this rule, so they fall through to the next rule (the unconditional `allow if dst_port == 22`) and are let through.

The behavior, in plain language: each source IP gets 10 free SSH connection attempts per second. Beyond that, additional attempts are dropped. Other source IPs are unaffected.

Generic per-source rate limit:

```python
# Drop any traffic from a source IP exceeding 5000 packets/second
drop limited by rate_limit(5000, per=src_ip)
allow
```

A rule may carry a `limited by` modifier without an `if` clause. The rule's action is gated by the rate limit alone — when no `if` is given, the rule applies to every packet, and the rate limit decides whether the action fires.

### Rate Limit Counters

Rate limit counters live in a per-CPU hash map. Entries that aren't updated for 60 seconds are eligible for eviction by an LRU policy when the map fills. The map size is fixed at compile time at 4096 entries; programs that need more buckets are an error to compile in v0.1.

If the map is full and an eviction would be needed for a new entry, the new entry is dropped silently — the rule treats the new bucket as "below threshold" until an existing entry expires. This is a known v0.1 limitation; v0.2 may replace the data structure.

## Named Counters

The `count <n>` action increments a named counter. Counter names are bare identifiers (`[a-z_][a-z0-9_]*`) declared by first use in the program. The compiler allocates one slot per unique name in a per-CPU array map sized at compile time.

Slot limit: 256 named counters per program. Programs with more than 256 distinct counter names fail to compile with `error: program declares <N> counters; v0.1 limit is 256`. Userspace tools read counters by name; the compiler emits a name → slot table alongside the BPF object so consumers can look up counters by their declared identifier.

A counter referenced by `count <n>` increments by exactly 1 for each packet matching the rule's condition. There is no decrement, no per-packet weight, no histogram. Future versions may add weighted counts (`count <n> by pkt.len`) and histograms.

## Logging

The `log` action writes an event to a BPF ring buffer. Userspace tools (the `f` orchestrator daemon, or external readers) consume the buffer and process the events.

```python
@xdp(eth0)

log if pkt.proto == tcp and pkt.dst_port == 22 and pkt.tcp.syn
drop if pkt.src_ip in 10.0.0.0/8
allow
```

In v0.1, log events have a fixed structure:

```
struct log_event {
    u64 timestamp_ns;       // bpf_ktime_get_ns() at time of log
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;           // 0 if not TCP/UDP
    u16 dst_port;           // 0 if not TCP/UDP
    u8  proto;              // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP
    u8  flags;              // bit 0 = SYN, bit 1 = ACK
    u32 rule_index;         // 0-indexed position of the rule in the .fw file
};
```

No custom log message strings in v0.1. No sampling. No log levels. Every `log` rule that matches writes one event. Userspace consumers can filter by `rule_index` to identify which rule produced an event.

## Compilation

The v0.1 compiler is a Python program that transforms `.fw` source into BPF C, then invokes clang to produce BPF bytecode.

### Pipeline

```
foo.fw  ──parse──▶  AST  ──semantic──▶  Typed AST  ──emit──▶  foo.bpf.c
                                                                 │
                                                            clang -target bpf
                                                                 │
                                                                 ▼
                                                              foo.bpf.o
                                                                 │
                                                              bpftool
                                                                 │
                                                                 ▼
                                                          attached to interface
```

### Compile-Time Errors

The compiler rejects programs with the following errors. Each error includes the source line number and a clear message.

| Condition | Error |
|---|---|
| Missing `@xdp` declaration | `error: program must declare a hook with @xdp(<interface>)` |
| `pkt` field access outside required protocol guard | `error: <field> requires <required guard>` |
| Type mismatch in comparison | `error: cannot compare <field> (<type>) with <literal> (<type>)` |
| Rate limit threshold non-positive | `error: rate_limit threshold must be > 0` |
| Rate limit `per` field is not a valid field | `error: rate_limit per= must be src_ip, dst_ip, src_port, or dst_port` |
| CIDR has invalid prefix length | `error: CIDR prefix must be 0..32 for IPv4` |
| Port literal outside 0..65535 | `error: port value <N> outside valid range 0..65535` |
| Range with `lo > hi` | `error: range lower bound (<lo>) exceeds upper bound (<hi>)` |
| Unknown identifier or built-in | `error: unknown identifier '<name>'` |
| Rule following a `default` rule | `error: 'default' must be the last rule in the program` |
| Non-terminal action as default | `error: 'default' action must be 'allow' or 'drop'; '<action>' is non-terminal` |
| Too many named counters | `error: program declares <N> counters; v0.1 limit is 256` |
| Use of v0.2+ feature | `error: <feature> not supported in v0.1` |

Errors are fatal. The compiler does not attempt to recover and parse the rest of the file; it reports the first error and exits.

### Runtime Errors

There are no runtime errors in FWL. The verifier-accepted BPF program either matches a rule and returns `XDP_DROP`, matches a rule and returns `XDP_PASS`, or matches no rule and returns `XDP_PASS`. There is no panic, no exception, no abort.

If the BPF verifier rejects the generated program, the compiler reports the verifier's error message verbatim. This is not expected for v0.1 — the language surface is small enough that all valid programs should verify — but a verifier rejection is treated as a compiler bug to be fixed, not a user error.

## Examples

### Block traffic from blocked countries

Not supported in v0.1 — `geoip()` is deferred. Use explicit CIDR blocks instead:

```python
@xdp(eth0)

# Block known bad-actor ranges (illustrative)
drop if pkt.src_ip in [
    198.51.100.0/24,
    203.0.113.0/24,
]

default allow
```

### SSH brute force protection

```python
@xdp(eth0)

# Allow up to 3 new SSH connections per second per source IP
drop if pkt.proto == tcp
       and pkt.dst_port == 22
       and pkt.tcp.syn and not pkt.tcp.ack
       limited by rate_limit(3, per=src_ip)

# Track allowed SSH connections for visibility
count ssh_allowed if pkt.proto == tcp and pkt.dst_port == 22
allow if pkt.proto == tcp and pkt.dst_port == 22

# Default: allow other traffic
default allow
```

### Web server with DDoS rate limit

```python
@xdp(eth0)

# Drop any source exceeding 1000 packets/sec
drop limited by rate_limit(1000, per=src_ip)

# Allow HTTP and HTTPS, count separately
count http_traffic  if pkt.proto == tcp and pkt.dst_port == 80
count https_traffic if pkt.proto == tcp and pkt.dst_port == 443
allow if pkt.proto == tcp and pkt.dst_port in [80, 443]

# Allow established outbound (heuristic: TCP without SYN)
allow if pkt.proto == tcp and not pkt.tcp.syn

# Drop everything else
default drop
```

### Internal network policy

```python
@xdp(eth0)

# Allow internal traffic
allow if pkt.src_ip in [10.0.0.0/8, 192.168.0.0/16]

# Allow established services
allow if pkt.proto == tcp and pkt.dst_port in [80, 443, 22]
allow if pkt.proto == udp and pkt.dst_port == 53

# Log unexpected attempts
log if pkt.proto == tcp and pkt.tcp.syn

# Default deny
default drop
```

### Discrimination by source/destination

```python
@xdp(eth0)

# Block specific bad source
drop if pkt.src_ip == 198.51.100.50

# Block any traffic to a specific destination port range from outside
drop if pkt.dst_port in 5000..6000
       and not pkt.src_ip in 10.0.0.0/8

allow
```

## Tooling

The v0.1 compiler ships as `fwl`, with these subcommands:

| Subcommand | Purpose |
|---|---|
| `fwl parse <file>` | Parse only. Print the AST. |
| `fwl check <file>` | Parse + semantic check. Report errors but do not generate code. |
| `fwl compile <file>` | Full compile to BPF. Output `.bpf.c` and `.bpf.o`. |
| `fwl test <dir>` | Run the test corpus against the compiler. |
| `fwl interpret <file> <pkt>` | Run the AST interpreter against a test packet. For development. |
| `fwl version` | Print version. |

Loading the compiled BPF onto an interface and managing it at runtime is the orchestrator daemon's job (`fd`), not the compiler's. v0.1's compiler produces `.bpf.o` files; the daemon handles attachment and lifecycle.

## What Is Not in v0.1

Restating the deferred list for clarity. None of the following are valid in v0.1; all produce compile errors with the message `<feature> not supported in v0.1`.

- IPv6: `pkt.src_ip6`, `pkt.dst_ip6`
- Tier 2 functions: `def`, control flow, locals, custom built-ins
- Tier 3: `inline_c`, `chain`, `.bpf.c` stage loading, `pkt.l4_payload`
- Built-ins beyond `rate_limit`: `geoip(...)`, `conntrack(pkt)`, `count(name)` as a function call (the `count <n>` action is in v0.1; the function-call form is deferred)
- `log(msg, sampled=N)` as a built-in function (the `log` action is in v0.1; the function-call form with custom messages and sampling is deferred)
- Custom protocol layers: `pkt.wg.*`, `pkt.icmp.*`, `pkt.dns.*`
- TCP flags beyond `syn` and `ack`
- IP options exposure
- Multi-interface attach (one `@xdp(<interface>)` per program)
- Multi-function programs (one rule sequence per program)
- Tail-call composition (`chain` keyword, pipeline stages)
- Dotted-call form (`conntrack(pkt).state == established`)
- Sampling on log (`log sampled 1/N`)
- String literals
- User-defined identifiers (no variables, no aliases, no functions)

## Grammar (Reference)

EBNF-style grammar for v0.1, for the parser implementation.

```ebnf
program       = hook_decl { rule } [ default_rule ] ;

hook_decl     = "@xdp" "(" identifier ")" ;

rule          = action [ "if" condition ] [ modifier ] ;

default_rule  = "default" terminal_action ;

action        = terminal_action | nonterminal_action ;
terminal_action    = "allow" | "drop" ;
nonterminal_action = "log" | "count" identifier ;

condition     = or_expr ;

or_expr       = and_expr { "or" and_expr } ;
and_expr      = not_expr { "and" not_expr } ;
not_expr      = [ "not" ] primary ;
primary       = comparison
              | bool_field
              | "(" condition ")" ;

comparison    = field comp_op operand
              | field "in" set_or_range ;

comp_op       = "==" | "!=" | "<" | ">" | "<=" | ">=" ;

field         = value_field | enum_field | bool_field ;

value_field   = "pkt.src_ip" | "pkt.dst_ip"
              | "pkt.src_port" | "pkt.dst_port" ;

enum_field    = "pkt.proto" ;

bool_field    = "pkt.tcp.syn" | "pkt.tcp.ack" ;

(* value_field groups ipv4 and u16 fields for parsing only;
   the semantic pass enforces type-correct comparisons —
   ordered comparisons (<, <=, >, >=) are restricted to u16
   port fields, and ipv4 fields require ipv4 or cidr operands. *)

operand       = integer | ipv4 | proto_keyword ;

proto_keyword = "tcp" | "udp" | "icmp" ;

set_or_range  = list | range | cidr | cidr_list ;
list          = "[" operand { "," operand } "]" ;
range         = integer ".." integer ;
cidr          = ipv4 "/" integer ;
cidr_list     = "[" cidr { "," cidr } "]" ;

modifier      = "limited" "by" "rate_limit" "(" integer "," "per" "=" rl_field ")" ;
rl_field      = "src_ip" | "dst_ip" | "src_port" | "dst_port" ;

ipv4          = octet "." octet "." octet "." octet ;
octet         = digit { digit } ;       (* semantic check: 0..255 *)
integer       = digit { digit }
              | "0x" hex_digit { hex_digit } ;
identifier    = letter_lower { letter_lower | digit | "_" } ;

letter_lower  = "a" | "b" | ... | "z" | "_" ;
digit         = "0" | "1" | ... | "9" ;
hex_digit     = digit | "a" | ... | "f" | "A" | ... | "F" ;
```

Notes on the grammar:

- A program may have zero rules between the hook declaration and an optional `default` rule. `@xdp(eth0)\ndefault drop` is a valid program (block all traffic).
- Boolean fields (`pkt.tcp.syn`, `pkt.tcp.ack`) appear directly as conditions; they evaluate to true when the bit is set. `if pkt.tcp.syn` is well-formed; `if pkt.tcp.syn == true` is not (no boolean literal in v0.1).
- The `not` operator applies to `bool_field` directly: `not pkt.tcp.ack` is valid.
- `octet` is `digit { digit }`; the parser accepts any non-empty digit sequence and the semantic pass enforces the 0..255 range. This avoids regular-grammar gymnastics for IPv4.
- `letter_lower` matches `[a-z]`. Identifiers do not start with digits and do not contain uppercase letters. This is a simplification from BNF rather than a feature: any characters outside `[a-z0-9_]` are illegal in v0.1 identifiers.

This grammar is the reference for the parser. Anything outside it is a syntax error.

## Summary

FWL v0.1 is a small, declarative language: one hook, a sequence of rules, three actions, seven `pkt` fields, one stateful primitive, IPv4 only, TCP/UDP/ICMP only. It compiles to verified BPF that runs at line rate. It expresses the firewall configurations operators actually write — port allow/deny, source/destination filtering, SYN flood and brute force protection, basic DDoS rate limiting.

Programs are short. Programs are readable. Programs do exactly what they say. v0.1's job is to deliver this surface correctly; v0.2 onward extends it.
