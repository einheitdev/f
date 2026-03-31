/// @file slow_path.cc
/// @brief Ring buffer consumer for slow-path decisions.

#include "f/slow_path.h"

#include <arpa/inet.h>
#include <cstring>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>

namespace f {

namespace {

/// libbpf ring_buffer callback. Invoked for each event.
auto RingBufCb(void* ctx, void* data, size_t size)
    -> int {
  if (size < sizeof(Event)) return 0;
  auto* sp = static_cast<SlowPath*>(ctx);
  auto* e = static_cast<const Event*>(data);
  sp->events_received++;
  if (sp->handler) {
    sp->handler(*e);
  } else {
    DefaultHandler(*sp, *e);
  }
  return 0;
}

auto IpStr(uint32_t addr) -> std::string {
  char buf[INET_ADDRSTRLEN];
  struct in_addr in;
  in.s_addr = addr;
  inet_ntop(AF_INET, &in, buf, sizeof(buf));
  return buf;
}

auto ProtoStr(uint8_t p) -> const char* {
  switch (p) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMP";
    default: return "?";
  }
}

}  // namespace

auto SlowPathInit(SlowPath& sp, int ringbuf_fd,
                  const BpfHandles& maps) -> bool {
  sp.ringbuf_fd = ringbuf_fd;
  sp.maps = maps;
  sp.rb = ::ring_buffer__new(
      ringbuf_fd, RingBufCb, &sp, nullptr);
  if (!sp.rb) {
    spdlog::error("ring_buffer__new failed.");
    return false;
  }
  spdlog::info("Slow path initialized.");
  return true;
}

auto SlowPathRun(SlowPath& sp, std::stop_token stop)
    -> void {
  spdlog::info("Slow path running.");
  while (!stop.stop_requested()) {
    // Poll with 100ms timeout.
    auto* rb = static_cast<::ring_buffer*>(sp.rb);
    int err = ::ring_buffer__poll(rb, 100);
    if (err < 0 && err != -EINTR) {
      spdlog::error("ring_buffer__poll: {}",
                    strerror(-err));
      break;
    }
  }
  spdlog::info("Slow path stopped. {} events, "
               "{} allowed, {} denied.",
               sp.events_received,
               sp.connections_allowed,
               sp.connections_denied);
}

auto SlowPathStop(SlowPath& sp) -> void {
  if (sp.rb) {
    ::ring_buffer__free(
        static_cast<::ring_buffer*>(sp.rb));
    sp.rb = nullptr;
  }
}

auto DefaultHandler(SlowPath& sp, const Event& e)
    -> void {
  uint8_t type = e.type;

  if (type == static_cast<uint8_t>(
          EventType::kNewConn)) {
    // New connection decision.
    // For now: allow all TCP/UDP, create conntrack entry.
    spdlog::debug(
        "New conn: {} {}:{} -> {}:{} ({}B)",
        ProtoStr(e.proto),
        IpStr(e.src_addr), e.src_port,
        IpStr(e.dst_addr), e.dst_port,
        e.pkt_len);

    // Inspect payload for basic protocol detection.
    bool allow = true;

    // DNS query inspection: if UDP port 53, check
    // for suspicious patterns.
    if (e.proto == 17 && e.dst_port == 53 &&
        e.pkt_len > 0) {
      // Payload starts at e.payload — first 64 bytes
      // of L4 payload. Could check DNS query name
      // against a blocklist here.
      spdlog::debug("DNS query detected.");
    }

    // HTTP host sniffing: if TCP port 80, first
    // bytes might be "GET " / "POST".
    if (e.proto == 6 && e.dst_port == 80) {
      // Check for HTTP method in payload (after TCP hdr).
      // The payload in the event starts at L4 offset,
      // so it includes the TCP header.
      spdlog::debug("HTTP connection detected.");
    }

    if (allow) {
      // Create conntrack entry so future packets
      // of this flow are handled at wire speed.
      ConnKey ckey{};
      ckey.src_addr = e.src_addr;
      ckey.dst_addr = e.dst_addr;
      ckey.src_port = e.src_port;
      ckey.dst_port = e.dst_port;
      ckey.proto = e.proto;

      ConnValue cval{};
      cval.last_seen_ns = e.timestamp_ns;
      cval.packets = 1;
      cval.state = 1;  // ESTABLISHED.

      bpf_map_update_elem(sp.maps.conntrack_fd,
                          &ckey, &cval, BPF_NOEXIST);
      sp.connections_allowed++;
    } else {
      sp.connections_denied++;
    }
  } else if (type == static_cast<uint8_t>(
                 EventType::kRateExceeded)) {
    spdlog::warn("Rate exceeded: {} {}:{} -> {}:{}",
                 ProtoStr(e.proto),
                 IpStr(e.src_addr), e.src_port,
                 IpStr(e.dst_addr), e.dst_port);
  }
}

}  // namespace f
