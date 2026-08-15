/// @file edit.h
/// @brief Reading and editing an FWL policy as text.
///
/// The `.fw` file is the policy. Until this module existed, nothing on
/// a box could put content into one: `new file` created an empty one
/// and `edit` shelled out to `$EDITOR`, which is not a CLI for a
/// firewall — it is a text editor with a firewall next to it.
///
/// What this is **not** is a second FWL front end. It does not parse
/// expressions, resolve helpers or know what a rule means. It knows
/// the *shape* of the document — `zone` declarations, `@xdp(...)`
/// blocks, and statements inside them — which is exactly enough to
/// number a rule, remove one, and put a new one in the right place.
/// The compiler stays the authority: every edit here is handed back as
/// text, and the caller runs `fwl check` on it before it is installed.
/// A policy that does not compile is never written over one that does.
///
/// **Order is the policy.** `allow` is terminal and `masquerade` /
/// `redirect` are unconditional, so a rule appended to the end of a
/// block is usually a rule that can never match. Placement is
/// therefore computed, not chosen by the caller, and reported back
/// with the statement it was placed in front of.

#ifndef INCLUDE_F_POLICY_EDIT_H_
#define INCLUDE_F_POLICY_EDIT_H_

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace f::policy {

/// What a statement does, as far as placement is concerned.
enum class Verb {
  /// `allow`, `drop`.
  kFilter,
  /// `dnat to ...`, `snat to ...`, `masquerade`.
  kTranslate,
  /// `redirect to <zone>`.
  kRedirect,
  /// `default allow` / `default drop`.
  kDefault,
  /// `count <name>`, `log`, `rate_limit` and anything else that does
  /// not decide a packet's fate on its own.
  kOther,
};

auto VerbName(Verb v) -> std::string;

/// One statement of a policy, located in the document.
struct Statement {
  /// 1-based position within its `@xdp` block, as `show policy`
  /// numbers it and `no rule` names it.
  int index = 0;
  /// The `@xdp(...)` block this belongs to. Empty for the prologue —
  /// the `zone` declarations and helper definitions above the first
  /// block.
  std::string zone;
  /// 1-based first line in the document.
  int line = 0;
  /// Number of lines the statement spans, continuations included.
  int lines = 1;
  /// The statement source, continuations folded onto one line and
  /// whitespace collapsed. This is what gets shown and matched.
  std::string text;
  Verb verb = Verb::kOther;
  /// True when the statement carries an `if` guard. An unguarded
  /// `allow`, `drop`, `masquerade` or `redirect` acts on every packet
  /// that reaches it, which is why nothing may be inserted after one.
  bool guarded = false;
};

/// A policy document as this module sees it.
struct PolicyView {
  /// Zones named by an `@xdp(...)` header, in document order.
  std::vector<std::string> zones;
  /// Zone names declared by a `zone <name> = [...]` line, in document
  /// order. A zone may be declared and have no block, or have a block
  /// and no declaration (the simple `@xdp(eth0)` form).
  std::vector<std::string> declared;
  std::vector<Statement> statements;

  /// Statements belonging to `zone`, in order.
  auto InZone(const std::string& zone) const
      -> std::vector<const Statement*>;
};

/// Read the shape of a policy document.
///
/// Never fails on content it does not understand — an unrecognised
/// statement is still a statement, and the compiler is what decides
/// whether it is legal.
auto ReadPolicy(std::string_view document) -> PolicyView;

/// Where an edit put a statement, so the reply can say so.
struct Placement {
  /// 1-based index the new statement now has in its block.
  int index = 0;
  /// 1-based line in the document.
  int line = 0;
  /// The statement it was placed in front of, or empty when it went
  /// at the end of the block.
  std::string before;
  /// Set when `before` is an unguarded action — the statement that
  /// would have swallowed the new rule had it been appended.
  bool before_is_unconditional = false;
};

/// The result of an edit: the new document and where the change went.
struct EditResult {
  std::string document;
  Placement placement;
  /// Statements the edit removed, as text.
  std::vector<std::string> removed;
  /// Anything the operator should be told that is not an error. A
  /// `redirect` left behind by the removal of its `dnat`, for
  /// instance, which the removal did not refuse but must not hide.
  std::vector<std::string> warnings;
};

/// A match condition, in the small vocabulary the CLI exposes.
///
/// Deliberately narrow. The point is not to reach FWL's expressive
/// power from a command line — it is that the changes an operator
/// makes weekly should not need an editor.
struct RuleSpec {
  /// `tcp`, `udp`, `icmp`, or empty for no protocol guard.
  std::string proto;
  /// Source address or CIDR; empty for none.
  std::string from;
  /// Destination address or CIDR; empty for none.
  std::string to;
  /// Destination port; 0 for none. Requires `proto` to be tcp or udp
  /// — **the compiler does not infer a protocol guard**, and without
  /// one the program reads whatever bytes sit at the port offset of,
  /// say, an ICMP packet.
  int port = 0;

  /// Render as an FWL condition, e.g.
  /// `pkt.proto == tcp and pkt.dst_port == 443`. Empty when nothing
  /// is set.
  auto Condition() const -> std::string;

  /// Why this spec cannot be turned into a rule, or empty.
  auto Refusal() const -> std::string;
};

/// Add `action` (`allow` or `drop`) guarded by `spec` to `zone`'s
/// block.
///
/// Placed at the end of the guarded region: after the last rule that
/// carries an `if`, and before the first unguarded action. Appending
/// to the end of the block would put it after `masquerade` /
/// `redirect` / `default`, where it could never match.
auto AddRule(std::string_view document, const std::string& zone,
             const std::string& action, const RuleSpec& spec)
    -> std::expected<EditResult, std::string>;

/// Remove statement `index` from `zone`'s block.
///
/// Comments above the statement are left alone: an operator's prose is
/// not ours to delete, and an orphaned comment is a smaller problem
/// than a missing explanation.
auto RemoveRule(std::string_view document, const std::string& zone,
                int index) -> std::expected<EditResult, std::string>;

/// A port forward: the `dnat` that rewrites the destination and the
/// `redirect` that emits the frame into the inside zone.
///
/// The two are written as one edit because `dnat` falls through and
/// does nothing on its own, and because a `redirect` whose guard is
/// wider than its `dnat`'s sends untranslated frames into the inside
/// zone. Both halves therefore always carry the same guard, which is
/// the mistake this verb exists to make impossible.
struct ForwardSpec {
  /// `tcp` or `udp`.
  std::string proto;
  /// The port as it arrives on `zone`.
  int port = 0;
  /// Where it goes, inside.
  std::string target_ip;
  int target_port = 0;
  /// The zone `target_ip` lives in — the caller derives it from the
  /// system configuration rather than asking the operator.
  std::string inside_zone;
  /// Optional source restriction, e.g. `10.1.0.0/16`.
  std::string from;

  auto Refusal() const -> std::string;
  /// The guard both halves carry.
  auto Condition() const -> std::string;
};

/// Add a forward to `zone`'s block, at the top of its guarded region.
///
/// A forward is a deliberate hole through the stateful rule below it,
/// so it goes where it can be seen, matching the shape in
/// `docs/howto/forward-a-port.md`.
auto AddForward(std::string_view document, const std::string& zone,
                const ForwardSpec& spec)
    -> std::expected<EditResult, std::string>;

/// Remove both halves of the forward for `proto`/`port` from `zone`.
///
/// Removing only one half is the failure mode; when only one is
/// found, it is removed and the result says which half was missing.
auto RemoveForward(std::string_view document, const std::string& zone,
                   const std::string& proto, int port)
    -> std::expected<EditResult, std::string>;

}  // namespace f::policy

#endif  // INCLUDE_F_POLICY_EDIT_H_
