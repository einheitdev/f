// A measurement, not a product component.
//
// The A4 design question is whether a TC *egress* hook is the right
// place to learn about flows the box itself originates. The whole
// recommendation rests on one claim about what such a hook can see:
//
//   * it sees every packet the local stack sends (DNS, NTP, updates —
//     exactly the flows XDP ingress conntrack is blind to), and
//   * it does NOT see traffic the XDP datapath forwards, because
//     bpf_redirect_map() leaves through ndo_xdp_xmit and never touches
//     the qdisc layer.
//
// If both hold, an egress conntrack tracker covers exactly the gap and
// costs nothing on the forwarding fast path. If the second does not
// hold, the same hook would double-count every forwarded packet and the
// design is wrong. So this counts IPv4 packets at egress and the
// scenario compares the delta across two bursts it generates
// deliberately: one from the local stack, one through XDP.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// <linux/pkt_cls.h> drags in headers that do not compile under
// `clang -target bpf` on every distro. TC_ACT_OK is 0 and has been
// since the classifier API existed.
#define FWL_TC_ACT_OK 0

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} fwl_probe_counts SEC(".maps");

SEC("tc")
int fwl_egress_probe(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return FWL_TC_ACT_OK;
  if (eth->h_proto != bpf_htons(ETH_P_IP)) return FWL_TC_ACT_OK;
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) return FWL_TC_ACT_OK;
  __u32 slot = 0;
  __u64 *c = bpf_map_lookup_elem(&fwl_probe_counts, &slot);
  if (c) __sync_fetch_and_add(c, 1);
  return FWL_TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
