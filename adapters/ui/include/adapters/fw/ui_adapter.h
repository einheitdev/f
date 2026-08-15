/// @file ui_adapter.h
/// @brief Factory for the f firewall web UI adapter.

#ifndef INCLUDE_ADAPTERS_FW_UI_ADAPTER_H_
#define INCLUDE_ADAPTERS_FW_UI_ADAPTER_H_

#include <memory>
#include <string>

#include "einheit/ui/adapter.h"

namespace einheit::adapters::fw {

/// Configuration for the f UI adapter.
///
/// No pin path: every page reads the daemon over `fd_socket`. The
/// adapter used to open the pinned maps itself, which is how it came to
/// carry its own copy of the v0.1 per-rule-counter defect, unreached by
/// the fix on the daemon side.
struct FwUiConfig {
  /// Raw ZMQ IPC endpoint for fd's control socket.
  std::string fd_socket = "ipc:///run/f/control.sock";
  /// Live-view sampling interval in milliseconds.
  int sample_interval_ms = 1000;
};

/// Create the f firewall UI adapter.
auto NewFwUiAdapter(FwUiConfig cfg)
    -> std::unique_ptr<ui::ProductUiAdapter>;

}  // namespace einheit::adapters::fw

#endif  // INCLUDE_ADAPTERS_FW_UI_ADAPTER_H_
