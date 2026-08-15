/// @file rules.h
/// @brief The rules of the policy that is LOADED, as an operator reads
/// them.
///
/// The question at the office is "what is this box enforcing right
/// now", and until this module existed the honest answer was "read the
/// `.fw` file and hope it matches". `fd` holds compiled BPF objects;
/// the bundle manifest carried per-zone topology and no rule metadata;
/// the daemon has never seen the policy text. `show policy` read the
/// source, which is not necessarily what is loaded, and the `/policy`
/// page stated the gap in place rather than filling it from the bundle
/// directory — a claim about the disk on a page whose whole claim is
/// the packet path.
///
/// The compiler now writes each zone's rules into `manifest.json` and
/// `LoadZoneBundle` captures them **in the same call that opens the
/// object**, exactly the way it captures the `// fwl_counter_table:`
/// block beside the counters map. Both halves come from one load or
/// from neither. Nothing re-reads the bundle directory afterwards,
/// because a consumer that did would be describing one policy's rules
/// while the box runs another's — which is the shape of the defect the
/// retired `kGetRules` shipped: it paired counters with rules by
/// iteration order while the datapath keyed them by match tier, so
/// every number it showed was wrong and next to the wrong rule.
///
/// There is deliberately no per-rule counter here. `count` names live
/// in counters.h and travel with their values; a rule and a counter
/// are joined by nothing in this API, and that is the point.

#ifndef INCLUDE_F_RULES_H_
#define INCLUDE_F_RULES_H_

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace f {

/// Why a zone's rule list looks the way it does.
///
/// Availability is a type, not a convention — the same decision
/// `CounterAvailability` and `LeaseAvailability` make, for the same
/// reason. "This zone has no rules" and "this box cannot say what this
/// zone's rules are" are opposite findings about a firewall and they
/// render identically if the reason is dropped.
enum class RuleAvailability : uint8_t {
  /// The rules below are this zone's whole policy, in policy order.
  kListed,
  /// This zone's policy is a default action and nothing else. A fact
  /// about the policy; nothing is wrong.
  kNoneDeclared,
  /// The zone is Tier 2: its policy is a function body, a statement
  /// tree with no rule list to give. Different from a zone with no
  /// rules, and reported differently, because a page that draws them
  /// the same way says a firewall with a policy has none.
  kFunctionForm,
  /// The loaded bundle carries no rule metadata for this zone at all —
  /// it was compiled by an `fwl` that predates this manifest field.
  /// This is "cannot ask", and it must never read as "no rules".
  kNotEmitted,
  /// The daemon reported a state this build has no word for. Reachable
  /// only across a version skew.
  kUnknown,
};

/// A short machine token — the wire word, and what a test asserts on.
auto RuleAvailabilityName(RuleAvailability a) -> std::string_view;

/// The inverse. A token this build has no state for is `kUnknown`,
/// never a fallback to one of the states that has a meaning.
auto RuleAvailabilityFromName(std::string_view s) -> RuleAvailability;

/// The operator's word for `a` — what the CLI table and the web page
/// both print. One definition, so a zone reads the same in the
/// terminal and on the screen.
auto RuleStateWord(RuleAvailability a) -> std::string_view;

/// What to print where a rule with no `if` would show its guard.
///
/// Three states, not two, and one definition of them. An unguarded
/// TERMINAL action stops every packet that reaches it and nothing
/// below it can match — the single most expensive thing to misread in
/// a policy. An unguarded `count` or `log` also runs on every packet
/// but falls through, and marking it the same way puts a warning
/// beside the one statement in the block that is harmless. An empty
/// cell is neither: it is indistinguishable from a guard this build
/// could not write down, which is the opposite claim.
///
/// One function because the CLI renders this twice (a table for a
/// person, a document for a script) and the web page a third time,
/// and three copies of the wording drift into a box that says one
/// thing in the terminal and another on the screen for the same rule.
auto UnguardedMatchWord(bool terminal) -> std::string_view;

/// One rule of a loaded policy.
struct LoadedRule {
  /// The index this rule's log events carry, which is the ONLY thing
  /// it may legitimately be joined against. Named for that rather than
  /// called `index`, because a bare index beside a list of values is
  /// how the retired rule surface came to attribute every count to the
  /// wrong rule.
  int log_rule_index = -1;
  /// 1-based line in the policy source this rule was compiled from.
  int line = 0;
  /// The action with its target: `redirect to wan`, `dnat to
  /// 10.0.0.5:8080`, `count lan_total`. One field, because a redirect
  /// whose zone is in another column is a redirect to the wrong place
  /// that nobody notices.
  std::string action;
  /// The guard, in FWL's own source form. Empty when the rule is
  /// unguarded — see `guarded`, which is what distinguishes that from
  /// a guard this build could not write.
  std::string match;
  /// The whole statement on one line: what an operator scans.
  std::string text;
  /// The `rate_limit(...)` modifier, or empty.
  std::string rate_limit;
  /// True when the rule carries an `if`. An unguarded terminal action
  /// runs on every packet that reaches it, and nothing below it can
  /// match.
  bool guarded = false;
  /// True for allow/drop/redirect: evaluation stops here.
  bool terminal = false;
  /// False when the compiler had no source form for some part of this
  /// rule's match. `match` is then empty and `omitted` says what was
  /// missing — never a shortened expression that reads as the whole
  /// guard.
  bool renderable = true;
  std::vector<std::string> omitted;
};

/// The action taken by whatever reaches the end of a zone's block.
///
/// `stated` is false when the policy has no `default` line, in which
/// case the program falls through to XDP_PASS and the zone ALLOWS
/// everything that gets there. Reporting that as "no default" would
/// put the most consequential line of a policy on the screen as a
/// blank.
struct DefaultAction {
  bool known = false;
  std::string action;
  int line = 0;
  bool stated = false;
};

/// One zone's rules as the loaded bundle declares them.
struct ZoneRules {
  std::string zone;
  RuleAvailability availability = RuleAvailability::kNotEmitted;
  /// One sentence on anything that could not be given. Empty on
  /// kListed with nothing omitted.
  std::string detail;
  std::vector<LoadedRule> rules;
  DefaultAction default_action;
  /// Rule indices where the emitter starts a new tail-call stage. The
  /// `chain` labels do not survive parsing and are not reported.
  std::vector<int> stage_boundaries;
};

/// The identity of the policy text a loaded bundle was compiled from.
struct PolicySource {
  /// False when the bundle names no source — an older `fwl`, or a
  /// bundle built from an AST rather than a file. An unknown source is
  /// a state; it is not a reason to compare against nothing and call
  /// the result a match.
  bool known = false;
  std::string path;
  std::string name;
  std::string sha256;
  uint64_t bytes = 0;
};

/// Parse one `manifest.json` `programs[]` entry's rule metadata.
///
/// Called by `LoadZoneBundle` from the manifest object it already
/// holds, in the loop iteration that opens the zone's object. An entry
/// with no `rules` key is `kNotEmitted` — the bundle predates this
/// field, and the box says it cannot answer rather than answering
/// "none".
auto ParseRuleTable(const nlohmann::json& program_entry,
                    std::string_view zone) -> ZoneRules;

/// Parse a manifest's `policy_source` object.
auto ParsePolicySource(const nlohmann::json& manifest) -> PolicySource;

/// What comparing the loaded policy against a file on disk found.
enum class SourceDrift : uint8_t {
  /// The file on disk is byte-for-byte the text this policy was
  /// compiled from.
  kMatch,
  /// It is not. Somebody edited a policy that has not been compiled
  /// and applied, and the box is enforcing the older one.
  kDiffers,
  /// The comparison could not be made: no source recorded in the
  /// bundle, or the file could not be read. Not a match, and not
  /// drift — saying either would be inventing an answer.
  kCannotTell,
};

auto SourceDriftName(SourceDrift d) -> std::string_view;
auto SourceDriftFromName(std::string_view s) -> SourceDrift;

/// A drift verdict and the sentence that goes with it.
struct SourceComparison {
  SourceDrift verdict = SourceDrift::kCannotTell;
  std::string text;
};

/// Compare a loaded policy's source identity against a digest taken
/// from disk.
///
/// `disk_sha256` is nullopt when the file could not be read;
/// `disk_path` is named in the sentence either way, because an
/// operator told "cannot tell" without being told which file is being
/// looked for has been told nothing.
auto CompareSource(const PolicySource& loaded,
                   const std::optional<std::string>& disk_sha256,
                   std::string_view disk_path) -> SourceComparison;

/// The wire shape, defined once so the daemon that writes it and the
/// two consumers that read it cannot drift apart.
auto ZoneRulesToJson(const std::vector<ZoneRules>& zones,
                     const PolicySource& source) -> nlohmann::json;

/// The inverse. Anything the payload does not carry comes back as
/// "could not be read" rather than as an empty rule list.
auto ZoneRulesFromJson(const nlohmann::json& j)
    -> std::vector<ZoneRules>;

auto PolicySourceFromJson(const nlohmann::json& j) -> PolicySource;

}  // namespace f

#endif  // INCLUDE_F_RULES_H_
