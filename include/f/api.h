/// @file api.h
/// @brief Crow REST API setup and handlers.

#ifndef INCLUDE_F_API_H_
#define INCLUDE_F_API_H_

#include <memory>
#include <string>

#include <crow.h>

#include "f/daemon.h"
#include "f/log_sink.h"

namespace f {

/// Shared data passed to all API endpoint handlers.
struct ApiData {
  Daemon* daemon;
  std::shared_ptr<RingBufferSink_mt> log_sink;
  uint16_t api_port;
  std::string static_dir;
};

/// Register all REST + HTMX routes on the Crow app.
auto SetupRoutes(crow::SimpleApp& app,
                 std::shared_ptr<ApiData> data) -> void;

/// Run the Crow HTTP server (called on the API jthread).
auto RunApi(std::stop_token stop,
            std::shared_ptr<ApiData> data) -> void;

}  // namespace f

#endif  // INCLUDE_F_API_H_
