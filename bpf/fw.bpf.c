/// @file fw.bpf.c
/// @brief XDP firewall program.
///
/// Uses inline struct definitions instead of kernel headers to
/// avoid pulling in glibc through transitive includes.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "f/types.h"

// Minimal protocol/header definitions to avoid glibc.
#define ETH_P_IP 0x0800

struct ethhdr {
  unsigned char h_dest[6];
  unsigned char h_source[6];
  __be16 h_proto;
} __attribute__((packed));

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  __u8 ihl:4, version:4;
#else
  __u8 version:4, ihl:4;
#endif
  __u8 tos;
  __be16 tot_len;
  __be16 id;
  __be16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __sum16 check;
  __be32 saddr;
  __be32 daddr;
};

struct tcphdr {
  __be16 source;
  __be16 dest;
  __be32 seq;
  __be32 ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1,
        ack:1, urg:1, ece:1, cwr:1;
#else
  __u16 doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1,
        psh:1, rst:1, syn:1, fin:1;
#endif
  __be16 window;
  __sum16 check;
  __be16 urg_ptr;
};

struct udphdr {
  __be16 source;
  __be16 dest;
  __be16 len;
  __sum16 check;
};

#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

// ============================================================================
// Map definitions
// ============================================================================

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct RuleKey);
  __type(value, struct RuleValue);
} rules_a SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct RuleKey);
  __type(value, struct RuleValue);
} rules_b SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 10000);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct LpmKey);
  __type(value, struct RuleValue);
} cidr_a SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 10000);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct LpmKey);
  __type(value, struct RuleValue);
} cidr_b SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct ConnKey);
  __type(value, struct ConnValue);
} conntrack SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 10000);
  __type(key, __u32);
  __type(value, struct RuleCounter);
} counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct FwConfig);
} config SEC(".maps");

// ============================================================================
// Helpers
// ============================================================================

static __always_inline int apply_action(
    struct RuleValue* val, __u32 rule_id, __u32 pkt_len) {
  struct RuleCounter* ctr =
      bpf_map_lookup_elem(&counters, &rule_id);
  if (ctr) {
    ctr->packets += 1;
    ctr->bytes += pkt_len;
  }
  if (val->action == ACTION_DROP) {
    return XDP_DROP;
  }
  return XDP_PASS;
}

// ============================================================================
// XDP program
// ============================================================================

SEC("xdp")
int fw_prog(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;

  // Parse Ethernet header.
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > data_end) {
    return XDP_PASS;
  }
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // Parse IP header.
  struct iphdr* ip = (void*)(eth + 1);
  if ((void*)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // Read global config.
  __u32 cfg_key = 0;
  struct FwConfig* cfg =
      bpf_map_lookup_elem(&config, &cfg_key);
  if (!cfg) {
    return XDP_PASS;
  }

  // Extract ports for TCP/UDP.
  __u16 src_port = 0;
  __u16 dst_port = 0;
  __u32 l4_off = sizeof(*eth) + (ip->ihl * 4);

  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr* tcp = data + l4_off;
    if ((void*)(tcp + 1) > data_end) {
      return XDP_PASS;
    }
    src_port = bpf_ntohs(tcp->source);
    dst_port = bpf_ntohs(tcp->dest);
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr* udp = data + l4_off;
    if ((void*)(udp + 1) > data_end) {
      return XDP_PASS;
    }
    src_port = bpf_ntohs(udp->source);
    dst_port = bpf_ntohs(udp->dest);
  }

  __u32 pkt_len = data_end - data;

  // Always increment counter 0 for total traffic visibility.
  __u32 total_key = 0;
  struct RuleCounter* total_ctr =
      bpf_map_lookup_elem(&counters, &total_key);
  if (total_ctr) {
    total_ctr->packets += 1;
    total_ctr->bytes += pkt_len;
  }

  // Try progressively looser keys until one matches.
  // Most specific first: full 5-tuple, then wildcards.
  // Zero = wildcard in rule key.
  struct RuleKey keys[5];
  // 0: full 5-tuple
  keys[0] = (struct RuleKey){
      .src_addr = ip->saddr, .dst_addr = ip->daddr,
      .src_port = src_port, .dst_port = dst_port,
      .proto = ip->protocol,
  };
  // 1: wildcard src_port
  keys[1] = (struct RuleKey){
      .src_addr = ip->saddr, .dst_addr = ip->daddr,
      .dst_port = dst_port, .proto = ip->protocol,
  };
  // 2: dst + dst_port + proto only
  keys[2] = (struct RuleKey){
      .dst_addr = ip->daddr,
      .dst_port = dst_port, .proto = ip->protocol,
  };
  // 3: dst_port + proto only (any src/dst)
  keys[3] = (struct RuleKey){
      .dst_port = dst_port, .proto = ip->protocol,
  };
  // 4: proto only (any addr/port)
  keys[4] = (struct RuleKey){
      .proto = ip->protocol,
  };

  struct RuleValue* val = 0;
  for (int k = 0; k < 5; k++) {
    if (cfg->active_table == 0) {
      val = bpf_map_lookup_elem(&rules_a, &keys[k]);
    } else {
      val = bpf_map_lookup_elem(&rules_b, &keys[k]);
    }
    if (val) {
      return apply_action(val, k + 1, pkt_len);
    }
  }

  // Fallback: CIDR lookup on source IP.
  struct LpmKey lkey = {
      .prefixlen = 32,
      .addr = ip->saddr,
  };
  if (cfg->active_table == 0) {
    val = bpf_map_lookup_elem(&cidr_a, &lkey);
  } else {
    val = bpf_map_lookup_elem(&cidr_b, &lkey);
  }
  if (val) {
    return apply_action(val, 1, pkt_len);
  }

  // Connection tracking.
  if (cfg->conntrack_enabled) {
    struct ConnKey ckey = {
        .src_addr = ip->saddr,
        .dst_addr = ip->daddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = ip->protocol,
    };
    struct ConnValue* cval =
        bpf_map_lookup_elem(&conntrack, &ckey);
    if (cval) {
      cval->last_seen_ns = bpf_ktime_get_ns();
      cval->packets += 1;
      return XDP_PASS;
    }

    // Check reverse direction (reply).
    struct ConnKey rkey2 = {
        .src_addr = ip->daddr,
        .dst_addr = ip->saddr,
        .src_port = dst_port,
        .dst_port = src_port,
        .proto = ip->protocol,
    };
    cval = bpf_map_lookup_elem(&conntrack, &rkey2);
    if (cval) {
      struct ConnValue new_val = {
          .last_seen_ns = bpf_ktime_get_ns(),
          .packets = 1,
          .state = 1,
      };
      bpf_map_update_elem(
          &conntrack, &ckey, &new_val, BPF_NOEXIST);
      return XDP_PASS;
    }
  }

  // Default action.
  if (cfg->default_action == ACTION_DROP) {
    return XDP_DROP;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
