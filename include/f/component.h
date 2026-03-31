/// @file component.h
/// @brief Base pattern for all stateful components.
///
/// Every component in the firewall implements this
/// interface. The engine aggregates state by calling
/// GetState() on each component.

#ifndef INCLUDE_F_COMPONENT_H_
#define INCLUDE_F_COMPONENT_H_

#include <nlohmann/json.hpp>

namespace f {

/// Base for any component that reports state.
struct Component {
  virtual ~Component() = default;

  /// Return current state as JSON.
  virtual auto GetState() const -> nlohmann::json = 0;

  /// Apply state update from JSON. Returns true if
  /// the component accepted the update.
  virtual auto SetState(const nlohmann::json& j)
      -> bool = 0;
};

}  // namespace f

#endif  // INCLUDE_F_COMPONENT_H_
