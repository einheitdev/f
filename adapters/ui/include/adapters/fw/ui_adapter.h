/// @file ui_adapter.h
/// @brief Factory for the f firewall web UI adapter.

#ifndef INCLUDE_ADAPTERS_FW_UI_ADAPTER_H_
#define INCLUDE_ADAPTERS_FW_UI_ADAPTER_H_

#include <memory>
#include <string>

#include "einheit/ui/adapter.h"

namespace einheit::adapters::fw {

/// Configuration for the f UI adapter.
struct FwUiConfig {
  /// bpffs pin path where fd pins its maps.
  std::string pin_path = "/sys/fs/bpf/f";
  /// Raw ZMQ IPC endpoint for fd's control socket.
  std::string fd_socket = "ipc:///tmp/fd-control.sock";
  /// Counter sampling interval in milliseconds.
  int sample_interval_ms = 1000;
};

/// Create the f firewall UI adapter.
auto NewFwUiAdapter(FwUiConfig cfg)
    -> std::unique_ptr<ui::ProductUiAdapter>;

}  // namespace einheit::adapters::fw

#endif  // INCLUDE_ADAPTERS_FW_UI_ADAPTER_H_
