/// @file views.cc
/// @brief The daemon's answers turned into what a page renders.

#include "adapters/fw/views.h"

#include <algorithm>
#include <format>
#include <string>
#include <vector>

#include "f/counters.h"
#include "f/rules.h"

namespace einheit::adapters::fw {
namespace {

using json = nlohmann::json;

/// The badge classes the stylesheet actually defines. A semantic
/// outside this set renders as an unstyled badge, which is the same
/// grey whatever it means.
constexpr const char* kGood = "good";
constexpr const char* kWarn = "warn";
constexpr const char* kBad = "bad";
constexpr const char* kInfo = "info";

/// How a zone's availability should read on a page.
///
/// `read` is the only good state; `none_declared` is a fact about the
/// policy and nothing is wrong with it; every other state is a zone
/// whose numbers this box cannot give, which is a finding.
auto StateSemanticFor(::f::CounterAvailability a) -> const char* {
  switch (a) {
    case ::f::CounterAvailability::kRead: return kGood;
    case ::f::CounterAvailability::kNoneDeclared: return kInfo;
    default: return kBad;
  }
}

/// True when fd's reply is the shape opcode 12 agreed to send.
///
/// An answer arriving is not an answer. An `fd` too old to know
/// opcode 12 replies `unknown command`, and anything else that is not
/// this shape is a version skew: it is reported, never rendered as a
/// box with no counters on it.
auto HasZonesArray(const json& body) -> bool {
  return body.is_object() && body.contains("zones") &&
         body["zones"].is_array();
}

constexpr const char* kSkewText =
    "fd answered the counter query with a payload carrying no zones — "
    "this box's fd is not the one this UI expects. Check that fd and "
    "einheit-f-ui are from the same build.";

}  // namespace

auto UnavailableText(const FdAnswer& answer,
                     std::string_view empty_text) -> std::string {
  if (answer.ok) return std::string(empty_text);
  return "cannot read this from fd: " + answer.error;
}

auto JoinArr(const json& arr) -> std::string {
  std::string out;
  if (!arr.is_array()) return out;
  for (const auto& s : arr) {
    if (!s.is_string()) continue;
    if (!out.empty()) out += ", ";
    out += s.get<std::string>();
  }
  return out;
}

auto DecorateZones(json zones) -> json {
  if (!zones.is_array()) return json::array();
  for (auto& z : zones) {
    z["ifaces_str"] = JoinArr(z.value("interfaces", json::array()));
    z["attached_str"] = JoinArr(z.value("attached", json::array()));
    if (z["attached_str"].get<std::string>().empty()) {
      z["attached_str"] = "(none)";
    }
    auto redir = JoinArr(z.value("redirects_to", json::array()));
    z["redirects_str"] = redir.empty() ? "-" : redir;
    bool masq = z.value("masquerades", false);
    z["masq_str"] = masq ? "yes" : "no";
    z["masq_semantic"] = masq ? kGood : "dim";
    z["attach_semantic"] =
        z.value("attached_count", 0) > 0 ? kGood : kWarn;
    auto mode = z.value("xdp_mode", std::string("-"));
    if (mode.empty()) mode = "-";
    z["xdp_mode"] = mode;
    z["mode_semantic"] = mode == "native"    ? kGood
                         : mode == "generic" ? kWarn
                                             : "dim";
  }
  return zones;
}

auto DecorateConntrack(json entries) -> json {
  if (!entries.is_array()) return json::array();
  for (auto& c : entries) {
    auto st = c.value("state", "");
    c["state_semantic"] = st == "established" ? kGood
                          : st == "invalid"   ? kBad
                                              : kWarn;
  }
  return entries;
}

auto CountersView(const FdAnswer& answer) -> json {
  json out;
  out["zones"] = json::array();
  out["notes"] = json::array();
  out["zone_count"] = 0;
  if (!answer.ok) {
    out["answered"] = false;
    out["unavailable"] =
        "cannot read counters from fd: " + answer.error;
    return out;
  }
  if (!HasZonesArray(answer.body)) {
    out["answered"] = false;
    out["unavailable"] = kSkewText;
    return out;
  }
  out["answered"] = true;
  out["unavailable"] = "";
  json zones = json::array();
  json notes = json::array();
  for (const auto& z : answer.body["zones"]) {
    if (!z.is_object()) continue;
    auto zone = z.value("zone", std::string{});
    auto token = z.value("availability", std::string{});
    auto avail = ::f::CounterAvailabilityFromName(token);
    auto detail = z.value("detail", std::string{});
    json rows = json::array();
    for (const auto& c : z.value("counters", json::array())) {
      if (!c.is_object()) continue;
      bool read = c.value("read", false);
      auto packets = c.value("packets", std::uint64_t{0});
      rows.push_back({
          {"name", c.value("name", std::string{})},
          {"slot", c.value("slot", 0U)},
          {"read", read},
          // A slot that could not be read renders as a word, never as
          // a zero. "Nothing hit this rule" and "nobody could ask"
          // are the two answers an operator must never see spelled
          // the same way.
          {"value", read ? std::to_string(packets) : "unreadable"},
          {"value_semantic",
           read ? (packets > 0 ? kGood : "dim") : kBad},
      });
    }
    // kRead with nothing in it should not happen — a zone declaring
    // no counters is `none_declared` — so say that rather than draw a
    // blank row.
    bool empty_read =
        avail == ::f::CounterAvailability::kRead && rows.empty();
    zones.push_back({
        {"zone", zone},
        {"availability",
         std::string(::f::CounterAvailabilityName(avail))},
        {"state_word",
         empty_read
             ? std::string("read, but no counters returned")
             : std::string(::f::CounterStateWord(avail))},
        {"state_semantic", empty_read ? kBad : StateSemanticFor(avail)},
        // The table draws rows when there are rows and the zone's own
        // state word when there are not; either way the zone occupies
        // a line.
        {"has_rows", !rows.empty()},
        {"row_count", rows.size()},
        {"map_slots", z.value("map_slots", 0U)},
        {"detail", detail},
        {"rows", rows},
    });
    if (!detail.empty()) {
      notes.push_back(std::format("{}: {}", zone, detail));
    }
  }
  out["zone_count"] = zones.size();
  out["zones"] = std::move(zones);
  out["notes"] = std::move(notes);
  out["empty_text"] = "fd reports no zone programs loaded";
  return out;
}

auto CountersSummary(const FdAnswer& answer) -> json {
  json out;
  if (!answer.ok || !HasZonesArray(answer.body)) {
    out["known"] = false;
    out["text"] = answer.ok
                      ? std::string(kSkewText)
                      : "cannot read counters from fd: " + answer.error;
    out["semantic"] = kBad;
    return out;
  }
  std::size_t named = 0;
  std::size_t counted_zones = 0;
  std::vector<std::string> blind;
  for (const auto& z : answer.body["zones"]) {
    if (!z.is_object()) continue;
    auto avail = ::f::CounterAvailabilityFromName(
        z.value("availability", std::string{}));
    if (avail == ::f::CounterAvailability::kRead) {
      auto n = z.value("counters", json::array()).size();
      named += n;
      if (n > 0) counted_zones++;
    } else if (avail != ::f::CounterAvailability::kNoneDeclared) {
      blind.push_back(z.value("zone", std::string{}));
    }
  }
  out["known"] = true;
  auto text = std::format("{} named in {} zone(s)", named,
                          counted_zones);
  if (!blind.empty()) {
    // The number beside it is a number ABOUT THE ZONES THAT COULD BE
    // READ. Reporting it on its own would let a box whose only
    // counted zone went unreadable read as a box with no counters.
    std::string names;
    for (const auto& b : blind) {
      if (!names.empty()) names += ", ";
      names += b;
    }
    text += std::format(" — {} unreadable: {}", blind.size(), names);
    out["semantic"] = kBad;
  } else {
    out["semantic"] = named > 0 ? kGood : kInfo;
  }
  out["text"] = text;
  return out;
}

auto PolicyView(const FdAnswer& zones, const FdAnswer& counters)
    -> json {
  json out;
  out["zones"] = json::array();
  out["zone_count"] = 0;
  if (!zones.ok) {
    out["answered"] = false;
    out["unavailable"] =
        "cannot read the loaded policy from fd: " + zones.error;
    return out;
  }
  if (!zones.body.is_array()) {
    out["answered"] = false;
    out["unavailable"] =
        "fd answered the zone query with something that is not a list "
        "of zones — this box's fd is not the one this UI expects.";
    return out;
  }
  out["answered"] = true;
  out["unavailable"] = "";

  // What each zone's LOADED policy declares it counts. The names were
  // captured by the load that put the program in the packet path, so
  // they belong to the policy that is running — not to whatever is in
  // the bundle directory now.
  bool counters_ok = counters.ok && HasZonesArray(counters.body);
  std::string counters_problem;
  if (!counters.ok) {
    counters_problem = "cannot read from fd";
  } else if (!counters_ok) {
    counters_problem = "fd answered with no counter zones";
  }

  json decorated = DecorateZones(zones.body);
  for (auto& z : decorated) {
    auto zone = z.value("zone", std::string{});
    if (!counters_ok) {
      z["counts_str"] = counters_problem;
      z["counts_semantic"] = kBad;
      continue;
    }
    const json* found = nullptr;
    for (const auto& c : counters.body["zones"]) {
      if (c.is_object() && c.value("zone", std::string{}) == zone) {
        found = &c;
        break;
      }
    }
    if (found == nullptr) {
      // Two answers from one daemon disagreeing about which zones are
      // loaded is a finding in itself, not a zone that counts nothing.
      z["counts_str"] = "not reported by fd";
      z["counts_semantic"] = kBad;
      continue;
    }
    auto avail = ::f::CounterAvailabilityFromName(
        found->value("availability", std::string{}));
    if (avail != ::f::CounterAvailability::kRead) {
      z["counts_str"] = std::string(::f::CounterStateWord(avail));
      z["counts_semantic"] = StateSemanticFor(avail);
      continue;
    }
    std::string names;
    for (const auto& c : found->value("counters", json::array())) {
      if (!c.is_object()) continue;
      if (!names.empty()) names += ", ";
      names += c.value("name", std::string{});
    }
    if (names.empty()) {
      z["counts_str"] = "read, but no counters returned";
      z["counts_semantic"] = kBad;
    } else {
      z["counts_str"] = names;
      z["counts_semantic"] = kInfo;
    }
  }
  out["zone_count"] = decorated.size();
  out["zones"] = std::move(decorated);
  out["empty_text"] =
      "fd has no zone programs loaded — nothing of the policy is in "
      "the packet path";
  return out;
}

auto PolicyRulesView(const FdAnswer& answer) -> json {
  json out;
  out["zones"] = json::array();
  out["zone_count"] = 0;
  out["rule_count"] = 0;
  out["source"] = {{"known", false}, {"text", ""}};
  if (!answer.ok) {
    out["answered"] = false;
    out["unavailable"] =
        "cannot read the loaded policy's rules from fd: " +
        answer.error;
    return out;
  }
  if (!HasZonesArray(answer.body)) {
    out["answered"] = false;
    out["unavailable"] =
        "fd answered the rule query with a payload carrying no "
        "zones — this box's fd is not the one this UI expects. Check "
        "that fd and einheit-f-ui are from the same build.";
    return out;
  }
  out["answered"] = true;
  out["unavailable"] = "";

  auto src = ::f::PolicySourceFromJson(answer.body);
  out["source"] = {
      {"known", src.known},
      {"name", src.name},
      {"path", src.path},
      // Enough of the digest to recognise, all of it to compare. The
      // full value is on the page so an operator can check it against
      // `sha256sum` on the file without leaving the screen.
      {"sha256", src.sha256},
      {"text",
       src.known
           ? std::format(
                 "compiled from {} (sha256 {}). `einheit-f show "
                 "policy` compares that against the file on disk; "
                 "this page reads no files.",
                 src.name.empty() ? src.path : src.name, src.sha256)
           : std::string(
                 "the loaded bundle records no policy source, so "
                 "nothing here can say which file it was compiled "
                 "from — recompile the policy to record one")}};

  std::size_t total = 0;
  json zones = json::array();
  for (const auto& z : ::f::ZoneRulesFromJson(answer.body)) {
    json rows = json::array();
    for (const auto& r : z.rules) {
      std::string match;
      const char* match_semantic = "dim";
      if (!r.guarded) {
        match = ::f::UnguardedMatchWord(r.terminal);
        match_semantic = r.terminal ? kWarn : "dim";
      } else if (!r.renderable) {
        match = "(a guard this build cannot render)";
        match_semantic = kBad;
      } else {
        match = r.match;
        match_semantic = "";
      }
      rows.push_back({
          {"action", r.action},
          {"match", match},
          {"match_semantic", match_semantic},
          {"rate_limit", r.rate_limit},
          {"terminal", r.terminal},
          {"line", r.line},
      });
    }
    total += rows.size();
    json def = nullptr;
    if (z.default_action.known) {
      def = {{"action", z.default_action.action},
             {"stated", z.default_action.stated},
             {"text",
              z.default_action.stated
                  ? std::format("default {}", z.default_action.action)
                  : std::format(
                        "default {} — no `default` line; the block "
                        "falls through to ALLOW",
                        z.default_action.action)},
             {"semantic",
              z.default_action.stated ? kInfo : kWarn}};
    }
    // A zone whose rules cannot be given still occupies a section,
    // with its own word for why. Vanishing from the page is how a box
    // that cannot describe its policy comes to look like a box with
    // no policy.
    zones.push_back({
        {"zone", z.zone},
        {"availability",
         std::string(::f::RuleAvailabilityName(z.availability))},
        {"state_word",
         std::string(::f::RuleStateWord(z.availability))},
        {"state_semantic",
         z.availability == ::f::RuleAvailability::kListed ? kGood
         : z.availability == ::f::RuleAvailability::kNoneDeclared
             ? kInfo
         : z.availability == ::f::RuleAvailability::kFunctionForm
             ? kInfo
             : kBad},
        {"has_rows", !rows.empty()},
        {"row_count", rows.size()},
        {"detail", z.detail},
        {"rows", rows},
        {"default", def},
    });
  }
  out["zone_count"] = zones.size();
  out["rule_count"] = total;
  out["zones"] = std::move(zones);
  out["empty_text"] =
      "fd has no zone programs loaded — nothing of the policy is in "
      "the packet path";
  return out;
}

auto PolicyFeatures(const FdAnswer& status) -> json {
  json rows = json::array();
  auto row = [&](const char* label, std::string value,
                 const char* semantic) {
    rows.push_back({{"label", label},
                    {"value", std::move(value)},
                    {"semantic", semantic}});
  };
  if (!status.ok || !status.body.is_object()) {
    row("connection tracking",
        "cannot read from fd: " + status.error, kBad);
    row("host-originated flows",
        "cannot read from fd: " + status.error, kBad);
    return rows;
  }
  auto ct = status.body.value("conntrack", json::object());
  if (ct.value("enabled", false)) {
    row("connection tracking",
        std::format("on — {} flow(s), {}s timeout",
                    ct.value("entries", 0U),
                    ct.value("timeout_s", 0U)),
        kGood);
  } else {
    row("connection tracking",
        "off — this policy asks no conntrack question", kInfo);
  }
  auto eg = status.body.value("egress", json::object());
  // `interfaces` is what the daemon attached the tracker to;
  // `attached` is HOW MANY of them carry it right now, asked of the
  // kernel. A count, not a list — read as a list it comes back empty
  // and a healthy box reports its own tracker as missing. That is
  // what this page did on deb-03 until the box was walked: a status
  // line that was false in the safe direction, which is still false.
  auto planned = eg.value("interfaces", json::array());
  auto names = JoinArr(planned);
  std::size_t want = planned.is_array() ? planned.size() : 0;
  std::size_t have = 0;
  if (eg.contains("attached") && eg["attached"].is_number()) {
    have = eg["attached"].get<std::size_t>();
  }
  if (!eg.value("tracker_declared", false)) {
    if (eg.value("bundle_predates_tracker", false)) {
      // The dangerous one: the policy reads conntrack and the bundle
      // has no hook to fill it, so the box's own replies answer NEW
      // and a `default drop` policy eats them.
      row("host-originated flows",
          "NOT tracked — this bundle was compiled before the egress "
          "tracker existed. The box's own DNS/NTP replies read as NEW.",
          kBad);
    } else {
      row("host-originated flows",
          "not tracked — this policy needs no tracker", kInfo);
    }
  } else if (have == 0) {
    row("host-originated flows",
        "DECLARED AND NOT ATTACHED — the hook this policy needs is "
        "not on any interface",
        kBad);
  } else if (have < want) {
    // The state the daemon reports two numbers for: somebody removed
    // the filter from some of the interfaces behind its back.
    row("host-originated flows",
        std::format("tracked on only {} of {} ({}) — the hook is gone "
                    "from the rest",
                    have, want, names),
        kBad);
  } else {
    row("host-originated flows",
        std::format("tracked on {}", names.empty()
                                         ? std::to_string(have)
                                         : names),
        kGood);
  }
  return rows;
}

}  // namespace einheit::adapters::fw
