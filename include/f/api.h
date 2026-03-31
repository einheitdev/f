/// @file api.h
/// @brief Crow REST API. Reads pinned BPF maps directly,
///        sends rule changes to engine via ZMQ.

#ifndef INCLUDE_F_API_H_
#define INCLUDE_F_API_H_

#include <memory>
#include <string>

#include <crow.h>

#include "f/bpf_loader.h"
#include "f/log_sink.h"

namespace f {

/// Shared data for all API handlers.
struct ApiData {
  BpfHandles maps;
  std::shared_ptr<RingBufferSink_mt> log_sink;
  std::string engine_addr;
  uint16_t api_port;
  std::string static_dir;
};

/// Register all REST + HTMX routes.
auto SetupRoutes(crow::SimpleApp& app,
                 std::shared_ptr<ApiData> data) -> void;

/// Run the Crow HTTP server (blocks until stop).
auto RunApi(std::stop_token stop,
            std::shared_ptr<ApiData> data) -> void;

}  // namespace f

#endif  // INCLUDE_F_API_H_
