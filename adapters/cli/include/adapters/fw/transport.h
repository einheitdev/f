/// @file transport.h
/// @brief Local transport for the f appliance CLI.
///
/// Reads BPF maps directly for show commands; forwards control
/// commands to fd over its existing raw ZMQ IPC socket. No
/// MessagePack on the wire — the CLI and daemon share a host.

#ifndef INCLUDE_ADAPTERS_FW_TRANSPORT_H_
#define INCLUDE_ADAPTERS_FW_TRANSPORT_H_

#include <expected>
#include <memory>
#include <string>

#include "einheit/cli/error.h"
#include "einheit/cli/transport/transport.h"

namespace einheit::adapters::fw {

/// Configuration for the local f transport.
struct FLocalConfig {
  /// bpffs pin path where fd pins its maps.
  std::string pin_path = "/sys/fs/bpf/f";
  /// Raw ZMQ IPC endpoint for fd's control socket.
  std::string fd_socket = "ipc:///run/f/control.sock";
  /// Path to the FWL source file.
  std::string fw_source = "/etc/f/rules.fw";
  /// Path to the fwl compiler.
  std::string fwl_path = "fwl";
  /// Preferred editor (overridden by set editor / $EDITOR).
  std::string editor = "vim";
  /// Persistent config file for CLI preferences.
  std::string config_path;
  /// The appliance system configuration: interfaces, zones, services.
  /// The single source of truth for everything the daemons are told.
  std::string system_config = "/etc/f/system.yaml";
  /// Where the generated dnsmasq artifact is installed. Derived from
  /// `system_config`; never hand-edited.
  std::string dnsmasq_conf = "/etc/f/generated/dnsmasq.conf";
  /// Where the generated networkd units are installed.
  std::string networkd_dir = "/etc/systemd/network";
  /// f-confd's control socket. f-confd owns the commit-confirmed
  /// revert timer, which has to outlive the session that armed it —
  /// so applying the system configuration goes through it whenever it
  /// is running.
  std::string confd_socket = "ipc:///run/f/confd.sock";
};

/// Construct a local transport that reads BPF maps in-process
/// and forwards control commands to fd over raw ZMQ.
auto NewFLocalTransport(const FLocalConfig& cfg)
    -> std::expected<
        std::unique_ptr<cli::transport::Transport>,
        cli::Error<cli::transport::TransportError>>;

}  // namespace einheit::adapters::fw

#endif  // INCLUDE_ADAPTERS_FW_TRANSPORT_H_
