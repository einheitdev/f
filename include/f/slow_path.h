/// @file slow_path.h
/// @brief Slow path: ring buffer consumer for complex
///        policy decisions on punted packets.

#ifndef INCLUDE_F_SLOW_PATH_H_
#define INCLUDE_F_SLOW_PATH_H_

#include <cstdint>
#include <functional>
#include <stop_token>
#include <string_view>

#include "f/bpf_loader.h"
#include "f/types.h"

namespace f {

/// Callback invoked for each event from the ring buffer.
using EventHandler = std::function<void(const Event&)>;

/// Slow path context.
struct SlowPath {
  int ringbuf_fd = -1;
  void* rb = nullptr;  // libbpf ring_buffer*.
  BpfHandles maps;
  EventHandler handler;

  // Stats.
  uint64_t events_received = 0;
  uint64_t connections_allowed = 0;
  uint64_t connections_denied = 0;
};

/// Initialize the slow path: open ring buffer, set handler.
auto SlowPathInit(SlowPath& sp,
                  int ringbuf_fd,
                  const BpfHandles& maps)
    -> bool;

/// Run the slow path poll loop (blocks until stop).
auto SlowPathRun(SlowPath& sp, std::stop_token stop)
    -> void;

/// Cleanup.
auto SlowPathStop(SlowPath& sp) -> void;

/// Default event handler: allows new TCP/UDP
/// connections, creates conntrack entries.
auto DefaultHandler(SlowPath& sp, const Event& e)
    -> void;

}  // namespace f

#endif  // INCLUDE_F_SLOW_PATH_H_
