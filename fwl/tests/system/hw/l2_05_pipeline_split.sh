#!/usr/bin/env bash
# Test-plan L2 row 4: pipeline split — identical behavior on the wire.
#
# The same rule set runs twice: once as a single program, once cut
# into tail-call stages with a `chain` marker (the manual form of the
# §6.6 auto-splitter; same splitter machinery, deterministic here).
# The daemon must resolve the staged entry (fwl_stage_0), wire the
# prog-array tail calls, and produce byte-identical wire behavior.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

RULES='count seen if pkt.src_ip in 10.99.31.0/24
drop if pkt.proto == tcp and pkt.dst_port == 9999
count survivors if pkt.src_ip in 10.99.31.0/24
allow if pkt.proto == tcp
default drop'

run_phase() {
  local tag="$1" body="$2" seen_var="$3" surv_var="$4" wire_var="$5"
  local fw
  fw=$(mktemp --suffix=.fw)
  printf 'zone t = [%s]\n\n@xdp(t)\n\n%s\n' "$RECV_IF" "$body" > "$fw"
  hw::deploy "$tag" "$fw"
  hw::sniff_start 6
  hw::send 100 'tcp(src_ip="10.99.31.5", dst_port=8443)'
  hw::send 100 'tcp(src_ip="10.99.31.5", dst_port=9999)'
  sleep 1
  hw::sniff_wait
  eval "$seen_var=\$(hw::counter seen)"
  eval "$surv_var=\$(hw::counter survivors)"
  eval "$wire_var=\$(hw::sniff_get tcp:10.99.31.5:8443)"
}

# Phase A: unsplit.
run_phase l2-05a "$RULES" SEEN_A SURV_A WIRE_A
# Phase B: the same rules with a forced stage cut.
SPLIT=$(printf '%s' "$RULES" \
  | sed 's/^count survivors/chain stage2\ncount survivors/')
run_phase l2-05b "$SPLIT" SEEN_B SURV_B WIRE_B

# The split bundle really is staged (not silently single-program).
grep -q "fwl_stage_0" "$BUNDLE_ROOT"/v-hw-l2-05b-*/t.bpf.c \
  && pass "split bundle carries fwl_stage_0 tail-call stages" \
  || fail "chain marker did not produce a staged program"

assert_eq "unsplit: seen" "$SEEN_A" 200
assert_eq "unsplit: survivors (9999 dropped in stage 1)" "$SURV_A" 100
assert_eq "unsplit: wire passed" "$WIRE_A" 100
assert_eq "split: seen equals unsplit" "$SEEN_B" "$SEEN_A"
assert_eq "split: survivors equals unsplit" "$SURV_B" "$SURV_A"
assert_eq "split: wire equals unsplit" "$WIRE_B" "$WIRE_A"
