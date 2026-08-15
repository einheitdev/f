/// @file views.h
/// @brief The daemon's answers turned into what a page renders.
///
/// These functions are the whole of the UI's judgement, kept out of
/// the Crow handlers on purpose: every one of them is reachable from a
/// unit test, and the decisions they make are the ones this surface
/// has got wrong before.
///
/// Two rules run through all of them.
///
/// **A reply arriving is not an answer.** `FdAnswer::ok` is false for
/// a daemon that is down, a request that timed out, and a reply
/// carrying `error` — and in every one of those cases a page must say
/// so rather than render an empty table. The removed `/firewall` page
/// said `no rules loaded` on every box ever deployed because it drew
/// the empty case for a question it never managed to ask.
///
/// **The four kinds of empty stay four.** `read`, `none_declared`,
/// `table_unreadable` and `table_map_mismatch` are different findings
/// about a firewall, and a page that renders all four as a blank table
/// undoes the whole reason fd distinguishes them. The words come from
/// `f::CounterStateWord`, which the CLI also uses, so a zone reads the
/// same in the terminal and on the screen.

#ifndef INCLUDE_ADAPTERS_FW_VIEWS_H_
#define INCLUDE_ADAPTERS_FW_VIEWS_H_

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace einheit::adapters::fw {

/// What fd said, and whether it is an answer at all.
struct FdAnswer {
  bool ok = false;
  /// fd's own words for why not, or why we could not reach it.
  std::string error;
  nlohmann::json body;
};

/// The message a view shows instead of a table: never a claim that the
/// thing is empty when the truth is that we could not read it.
auto UnavailableText(const FdAnswer& answer,
                     std::string_view empty_text) -> std::string;

/// Comma-join a JSON array of strings.
auto JoinArr(const nlohmann::json& arr) -> std::string;

/// Add the display fields the zones table renders (joined interface /
/// redirect lists, yes/no + semantic badges).
auto DecorateZones(nlohmann::json zones) -> nlohmann::json;

/// Tag each conntrack entry with a badge semantic for its state.
auto DecorateConntrack(nlohmann::json entries) -> nlohmann::json;

/// The counters page and the `fw.counters` live fragment.
///
/// `answer` is fd's reply to opcode 12. The result always carries
/// `answered`; when it is false the page prints `unavailable` and no
/// table at all, because "fd could not be asked" is not a count of
/// zero counters.
///
/// Every zone in the payload gets a row whatever its availability. A
/// zone that drops out of the table when its names cannot be read is
/// how a firewall with unreadable counters comes to look like a
/// firewall with none.
auto CountersView(const FdAnswer& answer) -> nlohmann::json;

/// The dashboard's counters line.
///
/// A measurement or an explicit failure — never a fixed badge. The
/// tile it replaces was an unconditional red `unavailable` that
/// nothing on the box ever set, which taught operators to skip the one
/// row that existed to catch the eye.
auto CountersSummary(const FdAnswer& answer) -> nlohmann::json;

/// The policy page: what fd has LOADED, per zone.
///
/// Joined from the two answers fd can give about the running policy —
/// the zone topology it attached (opcode 9) and the counters that
/// policy declares, captured at load time (opcode 12). Nothing here
/// reads the bundle directory or the `.fw` source: this page's claim
/// is "this is what is in the packet path", and a claim built from the
/// files on disk cannot support it.
///
/// It does not list rules, and the page says so rather than leaving a
/// gap that looks like a policy with no rules in it. fd holds compiled
/// objects; the bundle manifest carries no per-zone rule metadata and
/// the daemon has never seen the policy text.
auto PolicyView(const FdAnswer& zones, const FdAnswer& counters)
    -> nlohmann::json;

/// The two policy-wide facts a per-zone table cannot carry: whether
/// connections are tracked, and whether the flows the BOX ITSELF
/// starts are tracked with them.
///
/// Both are read out of fd's own status (opcode 3), where each is
/// already reported with its reason — an egress tracker that is off
/// because the policy asks no conntrack question and one that is off
/// because it was removed behind the daemon's back are different
/// boxes, and this returns different rows for them.
auto PolicyFeatures(const FdAnswer& status) -> nlohmann::json;

}  // namespace einheit::adapters::fw

#endif  // INCLUDE_ADAPTERS_FW_VIEWS_H_
