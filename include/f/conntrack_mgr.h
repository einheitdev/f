/// @file conntrack_mgr.h
/// @brief Connection tracking component.

#ifndef INCLUDE_F_CONNTRACK_MGR_H_
#define INCLUDE_F_CONNTRACK_MGR_H_

#include "f/component.h"
#include "f/types.h"

namespace f {

struct ConntrackMgr : Component {
  int map_fd = -1;
  bool enabled = false;
  uint32_t timeout_s = 300;

  auto GetState() const -> nlohmann::json override;
  auto SetState(const nlohmann::json& j) -> bool override;
};

}  // namespace f

#endif  // INCLUDE_F_CONNTRACK_MGR_H_
