/// @file rule_table.h
/// @brief Rule table component — owns the BPF rule maps.

#ifndef INCLUDE_F_RULE_TABLE_H_
#define INCLUDE_F_RULE_TABLE_H_

#include "f/bpf_loader.h"
#include "f/component.h"
#include "f/types.h"

namespace f {

struct RuleTable : Component {
  int rules_a_fd = -1;
  int rules_b_fd = -1;
  int config_fd = -1;
  int counters_fd = -1;
  uint8_t active_table = 0;

  auto GetState() const -> nlohmann::json override;
  auto SetState(const nlohmann::json& j) -> bool override;
};

}  // namespace f

#endif  // INCLUDE_F_RULE_TABLE_H_
