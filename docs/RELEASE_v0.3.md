# FWL v0.3 Release Notes

## Overview

v0.3 closes the verification gaps that limited hone's signal and adds
three language constructs operators need for production deployments.

## New Language Constructs

### Sampled `log(sample=N)`

`log(sample=N)` emits a ring buffer event for every N-th matching
packet. Prevents ring buffer overflow on high-throughput links.

```python
log(sample=100) if pkt.proto == tcp and pkt.dst_port in [80, 443]
```

`log` without `(sample=N)` is unchanged. `log(sample=1)` is
equivalent to bare `log`. The analyzer rejects `sample=0`.

### `count(name)` Function Form

`count(name)` as an expression inside if-conditions returns the
current counter value. Enables adaptive rules:

```python
count all_traffic
drop if pkt.proto == icmp and count(all_traffic) > 10000
```

All six comparison operators work. A counter not yet incremented
reads as 0.

### Conntrack GC

The `conntrack_timeout_s` config field is now honored. A userspace
GC pass in `ConntrackMgr::RunGc()` walks the pinned conntrack hash
map every `gc_interval_s` (default 30s) and evicts expired entries.

New config fields: `gc_interval_s` (default 30), `total_evicted`
(read-only).

## Harness Improvements

### `expected.counter_changes`

The runner asserts counter deltas from both oracles. The interpreter
tracks increments via `evaluate_full()`. The BPF runner reads the
per-CPU `fwl_counters` array. The loader validates counter names.

### `expected.log_events`

The runner asserts log events from both oracles. The interpreter
records `LogEvent` objects. The BPF runner drains the ring buffer
via `ring_buffer__consume`. Per-field partial matching.

### KB Post-Commit Hook

`f-knowlege-base/hooks/post-commit` calls
`hone index --kb . --incremental` after every KB commit.

## Corpus

524 total `.pkt` test cases (174 in-repo + 350 KB).

## Breaking Changes

None. All v0.1 and v0.2 programs compile unchanged.
