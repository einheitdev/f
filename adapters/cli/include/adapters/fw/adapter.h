/// @file adapter.h
/// @brief Factory for the f firewall CLI adapter.

#ifndef INCLUDE_ADAPTERS_FW_ADAPTER_H_
#define INCLUDE_ADAPTERS_FW_ADAPTER_H_

#include <memory>

#include "einheit/cli/adapter.h"

namespace einheit::adapters::fw {

/// Create the f firewall CLI adapter.
auto NewFwAdapter()
    -> std::unique_ptr<cli::ProductAdapter>;

}  // namespace einheit::adapters::fw

#endif  // INCLUDE_ADAPTERS_FW_ADAPTER_H_
