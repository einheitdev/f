// Minimal XDP pass program. Attached to the far end of each veth peer
// in the system-test topology: the kernel only delivers XDP_REDIRECT'd
// frames into a veth when that veth has an XDP program, so the peer
// needs this stub for redirected traffic to reach the normal stack
// (and tcpdump). It is pure test scaffolding — not part of fd.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
