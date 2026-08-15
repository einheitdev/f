/// @file rules.cc
/// @brief The loaded policy's rules: capture, states, and wire shape.

#include "f/rules.h"

#include <format>
#include <string>
#include <utility>
#include <vector>

namespace f {
namespace {

using json = nlohmann::json;

/// Read one rule object out of a manifest's per-zone rule array.
auto RuleFromJson(const json& r) -> LoadedRule {
  LoadedRule out;
  if (!r.is_object()) return out;
  out.log_rule_index = r.value("log_rule_index", -1);
  out.line = r.value("line", 0);
  out.action = r.value("action", std::string{});
  out.match = r.value("match", std::string{});
  out.text = r.value("text", std::string{});
  out.rate_limit = r.value("rate_limit", std::string{});
  out.guarded = r.value("guarded", false);
  out.terminal = r.value("terminal", false);
  out.renderable = r.value("renderable", true);
  for (const auto& o : r.value("omitted", json::array())) {
    if (o.is_string()) out.omitted.push_back(o.get<std::string>());
  }
  return out;
}

auto RuleToJson(const LoadedRule& r) -> json {
  json j = {
      {"log_rule_index", r.log_rule_index},
      {"line", r.line},
      {"action", r.action},
      {"match", r.match},
      {"text", r.text},
      {"rate_limit", r.rate_limit},
      {"guarded", r.guarded},
      {"terminal", r.terminal},
      {"renderable", r.renderable},
  };
  if (!r.omitted.empty()) j["omitted"] = r.omitted;
  return j;
}

}  // namespace

auto UnguardedMatchWord(bool terminal) -> std::string_view {
  return terminal ? "every packet — stops here"
                  : "every packet, falls through";
}

auto RuleAvailabilityName(RuleAvailability a) -> std::string_view {
  switch (a) {
    case RuleAvailability::kListed: return "listed";
    case RuleAvailability::kNoneDeclared: return "none_declared";
    case RuleAvailability::kFunctionForm: return "function_form";
    case RuleAvailability::kNotEmitted: return "not_emitted";
    case RuleAvailability::kUnknown: break;
  }
  return "unknown";
}

auto RuleAvailabilityFromName(std::string_view s) -> RuleAvailability {
  if (s == "listed") return RuleAvailability::kListed;
  if (s == "none_declared") return RuleAvailability::kNoneDeclared;
  if (s == "function_form") return RuleAvailability::kFunctionForm;
  if (s == "not_emitted") return RuleAvailability::kNotEmitted;
  return RuleAvailability::kUnknown;
}

auto RuleStateWord(RuleAvailability a) -> std::string_view {
  switch (a) {
    case RuleAvailability::kListed:
      return "listed";
    case RuleAvailability::kNoneDeclared:
      return "no rules — only a default action";
    case RuleAvailability::kFunctionForm:
      return "written as a function, not a rule list";
    case RuleAvailability::kNotEmitted:
      return "rules unknown — this bundle carries none";
    case RuleAvailability::kUnknown:
      break;
  }
  return "unknown state";
}

auto ParseRuleTable(const json& program_entry, std::string_view zone)
    -> ZoneRules {
  ZoneRules out;
  out.zone = std::string(zone);
  if (!program_entry.is_object() ||
      !program_entry.contains("rules") ||
      !program_entry["rules"].is_object()) {
    // The bundle was compiled before the compiler emitted rules. That
    // is "cannot ask", and it is why kNotEmitted exists rather than an
    // empty kListed: an old bundle would otherwise present as a policy
    // with no rules in it, which is a firewall that does nothing.
    out.availability = RuleAvailability::kNotEmitted;
    out.detail =
        "this bundle was compiled before the compiler emitted rule "
        "metadata; recompile the policy to see its rules here";
    return out;
  }
  const auto& r = program_entry["rules"];
  out.detail = r.value("detail", std::string{});
  const auto form = r.value("form", std::string{});
  for (const auto& b : r.value("stage_boundaries", json::array())) {
    if (b.is_number_integer()) out.stage_boundaries.push_back(b);
  }
  if (const auto& d = r["default"]; d.is_object()) {
    out.default_action.known = true;
    out.default_action.action = d.value("action", std::string{});
    out.default_action.line = d.value("line", 0);
    out.default_action.stated = d.value("explicit", false);
  }
  if (form == "function") {
    out.availability = RuleAvailability::kFunctionForm;
    return out;
  }
  if (form != "rules") {
    // A form this build has no word for. Reporting the rules under it
    // would be reporting a list whose meaning is not established.
    out.availability = RuleAvailability::kUnknown;
    out.detail = std::format(
        "this bundle describes zone {}'s policy as `{}`, which this "
        "build has no reading for", out.zone, form);
    return out;
  }
  for (const auto& rule : r.value("rules", json::array())) {
    out.rules.push_back(RuleFromJson(rule));
  }
  out.availability = out.rules.empty() ? RuleAvailability::kNoneDeclared
                                       : RuleAvailability::kListed;
  return out;
}

auto ParsePolicySource(const json& manifest) -> PolicySource {
  PolicySource out;
  if (!manifest.is_object() || !manifest.contains("policy_source") ||
      !manifest["policy_source"].is_object()) {
    return out;
  }
  const auto& s = manifest["policy_source"];
  out.path = s.value("path", std::string{});
  out.name = s.value("name", std::string{});
  out.sha256 = s.value("sha256", std::string{});
  out.bytes = s.value("bytes", uint64_t{0});
  // A recorded source with no digest cannot answer the question the
  // record exists for, so it is not "known".
  out.known = !out.sha256.empty();
  return out;
}

auto SourceDriftName(SourceDrift d) -> std::string_view {
  switch (d) {
    case SourceDrift::kMatch: return "match";
    case SourceDrift::kDiffers: return "differs";
    case SourceDrift::kCannotTell: break;
  }
  return "cannot_tell";
}

auto SourceDriftFromName(std::string_view s) -> SourceDrift {
  if (s == "match") return SourceDrift::kMatch;
  if (s == "differs") return SourceDrift::kDiffers;
  return SourceDrift::kCannotTell;
}

auto CompareSource(const PolicySource& loaded,
                   const std::optional<std::string>& disk_sha256,
                   std::string_view disk_path) -> SourceComparison {
  SourceComparison out;
  if (!loaded.known) {
    out.verdict = SourceDrift::kCannotTell;
    out.text =
        "the loaded bundle records no policy source, so this box "
        "cannot say whether the file on disk is the one it is running "
        "— recompile the policy to record one";
    return out;
  }
  if (!disk_sha256.has_value()) {
    out.verdict = SourceDrift::kCannotTell;
    out.text = std::format(
        "the loaded policy was compiled from {}, which could not be "
        "read here — whether the file still matches is unknown",
        disk_path.empty() ? loaded.path : std::string(disk_path));
    return out;
  }
  if (*disk_sha256 == loaded.sha256) {
    out.verdict = SourceDrift::kMatch;
    out.text = std::format(
        "{} is the policy that is loaded", disk_path);
    return out;
  }
  out.verdict = SourceDrift::kDiffers;
  out.text = std::format(
      "DRIFT: {} has been edited since this policy was compiled. The "
      "box is enforcing the OLDER one — the rules listed here are "
      "what is in the packet path, not what is in the file. "
      "`einheit-f reload firewall` compiles and applies the file.",
      disk_path);
  return out;
}

auto ZoneRulesToJson(const std::vector<ZoneRules>& zones,
                     const PolicySource& source) -> json {
  json arr = json::array();
  for (const auto& z : zones) {
    json rules = json::array();
    for (const auto& r : z.rules) rules.push_back(RuleToJson(r));
    json d = nullptr;
    if (z.default_action.known) {
      d = {{"action", z.default_action.action},
           {"line", z.default_action.line},
           {"stated", z.default_action.stated}};
    }
    arr.push_back({
        {"zone", z.zone},
        {"availability",
         std::string(RuleAvailabilityName(z.availability))},
        {"detail", z.detail},
        {"rules", std::move(rules)},
        {"default", std::move(d)},
        {"stage_boundaries", z.stage_boundaries},
    });
  }
  json src = {{"known", source.known}};
  if (source.known) {
    src["path"] = source.path;
    src["name"] = source.name;
    src["sha256"] = source.sha256;
    src["bytes"] = source.bytes;
  }
  return json{{"zones", std::move(arr)}, {"source", std::move(src)}};
}

auto ZoneRulesFromJson(const json& j) -> std::vector<ZoneRules> {
  std::vector<ZoneRules> out;
  if (!j.is_object() || !j.contains("zones") ||
      !j["zones"].is_array()) {
    return out;
  }
  for (const auto& z : j["zones"]) {
    if (!z.is_object()) continue;
    ZoneRules zr;
    zr.zone = z.value("zone", std::string{});
    // Absent availability is kUnknown, not kListed: a payload that
    // does not say why its rule list looks the way it does has not
    // told us that the list is complete.
    zr.availability = RuleAvailabilityFromName(
        z.value("availability", std::string{}));
    zr.detail = z.value("detail", std::string{});
    for (const auto& r : z.value("rules", json::array())) {
      zr.rules.push_back(RuleFromJson(r));
    }
    if (z.contains("default") && z["default"].is_object()) {
      const auto& d = z["default"];
      zr.default_action.known = true;
      zr.default_action.action = d.value("action", std::string{});
      zr.default_action.line = d.value("line", 0);
      zr.default_action.stated = d.value("stated", false);
    }
    for (const auto& b :
         z.value("stage_boundaries", json::array())) {
      if (b.is_number_integer()) zr.stage_boundaries.push_back(b);
    }
    out.push_back(std::move(zr));
  }
  return out;
}

auto PolicySourceFromJson(const json& j) -> PolicySource {
  PolicySource out;
  if (!j.is_object() || !j.contains("source") ||
      !j["source"].is_object()) {
    return out;
  }
  const auto& s = j["source"];
  out.path = s.value("path", std::string{});
  out.name = s.value("name", std::string{});
  out.sha256 = s.value("sha256", std::string{});
  out.bytes = s.value("bytes", uint64_t{0});
  out.known = s.value("known", false) && !out.sha256.empty();
  return out;
}

}  // namespace f
