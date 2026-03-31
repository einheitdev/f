/// @file iface_mgr.h
/// @brief Interface manager component — tracks XDP attachments.

#ifndef INCLUDE_F_IFACE_MGR_H_
#define INCLUDE_F_IFACE_MGR_H_

#include "f/component.h"

namespace f {

struct IfAttach {
  int ifindex;
  char name[16];
};

struct IfaceMgr : Component {
  IfAttach interfaces[16];
  uint32_t count = 0;

  auto GetState() const -> nlohmann::json override;
  auto SetState(const nlohmann::json& j) -> bool override;
};

}  // namespace f

#endif  // INCLUDE_F_IFACE_MGR_H_
