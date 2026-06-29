// A no-op XDP program (returns XDP_PASS).
//
// Attaching this to the *peer* of a veth used as an XDP_REDIRECT target
// is what enables veth's ndo_xdp_xmit path — without an XDP program on
// the receiving side, a redirected frame is dropped before it reaches
// the peer. Used by the zone-redirect netns system test to receive the
// frame the firewall redirects across zones.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
