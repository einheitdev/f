/// @file edit.cc
/// @brief Reading and editing an FWL policy as text.

#include "f/policy/edit.h"

#include <algorithm>
#include <cctype>
#include <format>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace f::policy {
namespace {

using Lines = std::vector<std::string>;

auto SplitLines(std::string_view text) -> Lines {
  Lines out;
  std::string cur;
  for (char c : text) {
    if (c == '\n') {
      out.push_back(cur);
      cur.clear();
    } else if (c != '\r') {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

auto Join(const Lines& lines) -> std::string {
  std::string out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    out += lines[i];
    if (i + 1 < lines.size()) out += '\n';
  }
  return out;
}

auto Indent(const std::string& line) -> std::size_t {
  std::size_t n = 0;
  while (n < line.size() && (line[n] == ' ' || line[n] == '\t')) ++n;
  return n;
}

auto IsBlankOrComment(const std::string& line) -> bool {
  auto n = Indent(line);
  return n >= line.size() || line[n] == '#';
}

/// The line with its trailing comment and surrounding space removed.
auto StripComment(const std::string& line) -> std::string {
  auto hash = line.find('#');
  auto body = hash == std::string::npos ? line : line.substr(0, hash);
  auto b = body.find_first_not_of(" \t");
  if (b == std::string::npos) return "";
  auto e = body.find_last_not_of(" \t");
  return body.substr(b, e - b + 1);
}

/// Whitespace collapsed to single spaces, so a statement spread over
/// three lines compares and prints as one.
auto Collapse(const std::string& text) -> std::string {
  std::string out;
  bool space = false;
  for (char c : text) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      space = !out.empty();
      continue;
    }
    if (space) out.push_back(' ');
    space = false;
    out.push_back(c);
  }
  return out;
}

auto FirstWord(const std::string& text) -> std::string {
  std::istringstream ss(text);
  std::string w;
  ss >> w;
  return w;
}

auto ClassifyVerb(const std::string& text) -> Verb {
  auto w = FirstWord(text);
  if (w == "allow" || w == "drop") return Verb::kFilter;
  if (w == "dnat" || w == "snat" || w == "masquerade") {
    return Verb::kTranslate;
  }
  if (w == "redirect") return Verb::kRedirect;
  if (w == "default") return Verb::kDefault;
  return Verb::kOther;
}

/// True when the collapsed statement carries an `if` guard. Matched as
/// a whole word so an identifier such as `if_index` is not one.
auto HasGuard(const std::string& text) -> bool {
  std::istringstream ss(text);
  std::string w;
  while (ss >> w) {
    if (w == "if") return true;
  }
  return false;
}

/// A statement that acts on every packet reaching it. Nothing may be
/// inserted after one of these and still match anything.
auto IsUnconditionalAction(const Statement& s) -> bool {
  if (s.guarded) return false;
  return s.verb == Verb::kFilter || s.verb == Verb::kTranslate ||
         s.verb == Verb::kRedirect || s.verb == Verb::kDefault;
}

/// The zone named by an `@xdp(<name>)` header, or empty.
auto XdpZone(const std::string& stripped) -> std::string {
  if (!stripped.starts_with("@xdp")) return "";
  auto open = stripped.find('(');
  auto close = stripped.rfind(')');
  if (open == std::string::npos || close == std::string::npos ||
      close <= open + 1) {
    return "";
  }
  auto inner = stripped.substr(open + 1, close - open - 1);
  auto b = inner.find_first_not_of(" \t");
  if (b == std::string::npos) return "";
  auto e = inner.find_last_not_of(" \t");
  return inner.substr(b, e - b + 1);
}

/// The zone named by a `zone <name> = [...]` declaration, or empty.
auto DeclaredZone(const std::string& stripped) -> std::string {
  if (!stripped.starts_with("zone ")) return "";
  std::istringstream ss(stripped);
  std::string kw, name;
  ss >> kw >> name;
  if (name.empty()) return "";
  auto eq = name.find('=');
  if (eq != std::string::npos) name = name.substr(0, eq);
  return name;
}

/// Where a statement lands in the document, once found.
struct Slot {
  /// Line index (0-based) to insert at.
  std::size_t at = 0;
  Placement placement;
};

/// The block header line for `zone`, or npos.
auto FindBlock(const Lines& lines, const std::string& zone)
    -> std::size_t {
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    if (XdpZone(StripComment(lines[i])) == zone) return i;
  }
  return std::string::npos;
}

/// The half-open line range of `zone`'s block body.
auto BlockRange(const Lines& lines, std::size_t header)
    -> std::pair<std::size_t, std::size_t> {
  for (std::size_t i = header + 1; i < lines.size(); ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    if (!XdpZone(StripComment(lines[i])).empty()) {
      return {header + 1, i};
    }
  }
  return {header + 1, lines.size()};
}

/// Skip back over blank lines and the comment block above `at`, so an
/// insertion lands above a comment that introduces the statement it is
/// being placed in front of rather than between the two.
auto SkipBackOverPrologue(const Lines& lines, std::size_t begin,
                          std::size_t at) -> std::size_t {
  while (at > begin && IsBlankOrComment(lines[at - 1])) --at;
  return at;
}

}  // namespace

auto VerbName(Verb v) -> std::string {
  switch (v) {
    case Verb::kFilter: return "filter";
    case Verb::kTranslate: return "translate";
    case Verb::kRedirect: return "redirect";
    case Verb::kDefault: return "default";
    case Verb::kOther: break;
  }
  return "other";
}

auto PolicyView::InZone(const std::string& zone) const
    -> std::vector<const Statement*> {
  std::vector<const Statement*> out;
  for (const auto& s : statements) {
    if (s.zone == zone) out.push_back(&s);
  }
  return out;
}

auto ReadPolicy(std::string_view document) -> PolicyView {
  auto lines = SplitLines(document);
  PolicyView view;
  std::string zone;
  int index = 0;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    // A continuation line is indented; it belongs to the statement
    // above it and is never a statement of its own.
    if (Indent(lines[i]) > 0) continue;
    auto stripped = StripComment(lines[i]);
    if (stripped.empty()) continue;

    auto header = XdpZone(stripped);
    if (!header.empty()) {
      zone = header;
      index = 0;
      if (std::find(view.zones.begin(), view.zones.end(), zone) ==
          view.zones.end()) {
        view.zones.push_back(zone);
      }
      continue;
    }
    auto declared = DeclaredZone(stripped);
    if (!declared.empty() && zone.empty()) {
      view.declared.push_back(declared);
    }

    // Fold the continuation lines in.
    std::string text = stripped;
    std::size_t span = 1;
    for (std::size_t j = i + 1; j < lines.size(); ++j) {
      if (IsBlankOrComment(lines[j])) break;
      if (Indent(lines[j]) == 0) break;
      text += " " + StripComment(lines[j]);
      span = j - i + 1;
    }

    Statement s;
    s.zone = zone;
    s.line = static_cast<int>(i) + 1;
    s.lines = static_cast<int>(span);
    s.text = Collapse(text);
    s.verb = ClassifyVerb(s.text);
    s.guarded = HasGuard(s.text);
    s.index = ++index;
    view.statements.push_back(std::move(s));
  }
  return view;
}

auto RuleSpec::Condition() const -> std::string {
  std::vector<std::string> terms;
  if (!proto.empty()) {
    terms.push_back(std::format("pkt.proto == {}", proto));
  }
  if (!from.empty()) {
    terms.push_back(std::format(
        "pkt.src_ip {} {}",
        from.find('/') == std::string::npos ? "==" : "in", from));
  }
  if (!to.empty()) {
    terms.push_back(std::format(
        "pkt.dst_ip {} {}",
        to.find('/') == std::string::npos ? "==" : "in", to));
  }
  if (port > 0) {
    terms.push_back(std::format("pkt.dst_port == {}", port));
  }
  std::string out;
  for (const auto& t : terms) {
    if (!out.empty()) out += " and ";
    out += t;
  }
  return out;
}

auto RuleSpec::Refusal() const -> std::string {
  if (!proto.empty() && proto != "tcp" && proto != "udp" &&
      proto != "icmp") {
    return std::format(
        "'{}' is not a protocol this verb knows — tcp, udp or icmp",
        proto);
  }
  if (port != 0 && (port < 1 || port > 65535)) {
    return std::format("port {} is outside 1-65535", port);
  }
  // The compiler does not infer protocol guards, and the reason is
  // better than the guess: without one, the program reads whatever
  // bytes sit at the port offset of an ICMP packet.
  if (port > 0 && proto != "tcp" && proto != "udp") {
    return "a port needs a protocol: say `tcp <port>` or "
           "`udp <port>`. FWL does not infer the guard, and without "
           "it the rule reads whatever bytes sit at the port offset "
           "of a packet that has no ports";
  }
  if (Condition().empty()) {
    return "a rule with no match condition acts on every packet — "
           "that is what `default allow` / `default drop` is for";
  }
  return "";
}

namespace {

/// The insertion point at the *end* of a block's guarded region.
///
/// Immediately after the last guarded statement, which is the end of
/// the list a new rule is being added to. Not merely "before the first
/// unconditional action": in the shape firstboot writes, `count
/// <zone>_out` sits under the comment that introduces the egress
/// group and above `masquerade`, and a rule dropped between the two
/// would be counted as egress and sit under a heading that is about
/// something else.
///
/// A block with no guarded statement at all falls back to the first
/// unconditional action, and then to the end of the block.
auto EndOfGuardedRegion(const Lines& lines, const std::string& zone,
                        std::size_t begin, std::size_t end,
                        const PolicyView& view)
    -> Slot {
  Slot slot;
  slot.at = end;
  auto stmts = view.InZone(zone);

  const Statement* last_guarded = nullptr;
  for (const auto* s : stmts) {
    if (s->guarded) last_guarded = s;
  }
  if (last_guarded != nullptr) {
    slot.at = static_cast<std::size_t>(last_guarded->line - 1 +
                                       last_guarded->lines);
    slot.placement.index = last_guarded->index + 1;
    for (const auto* s : stmts) {
      if (s->index != last_guarded->index + 1) continue;
      slot.placement.before = s->text;
      slot.placement.before_is_unconditional =
          IsUnconditionalAction(*s);
    }
    slot.placement.line = static_cast<int>(slot.at) + 1;
    return slot;
  }

  for (const auto* s : stmts) {
    if (!IsUnconditionalAction(*s)) continue;
    slot.at = static_cast<std::size_t>(s->line) - 1;
    slot.placement.index = s->index;
    slot.placement.before = s->text;
    slot.placement.before_is_unconditional = true;
    break;
  }
  if (slot.placement.before.empty()) {
    slot.placement.index = static_cast<int>(stmts.size()) + 1;
  }
  slot.at = SkipBackOverPrologue(lines, begin, slot.at);
  // Trailing blank lines at the very end of a block belong to the
  // separation from the next block, not to this statement.
  while (slot.at > begin && IsBlankOrComment(lines[slot.at - 1]) &&
         StripComment(lines[slot.at - 1]).empty() &&
         Indent(lines[slot.at - 1]) >= lines[slot.at - 1].size()) {
    --slot.at;
  }
  slot.placement.line = static_cast<int>(slot.at) + 1;
  return slot;
}

/// The insertion point at the *top* of a block's guarded region:
/// before the first statement that decides a packet's fate, after any
/// leading `count` / `log`.
auto TopOfGuardedRegion(const Lines& lines, const std::string& zone,
                        std::size_t begin, std::size_t end,
                        const PolicyView& view) -> Slot {
  Slot slot;
  slot.at = end;
  auto stmts = view.InZone(zone);
  for (const auto* s : stmts) {
    if (s->verb == Verb::kOther) continue;
    slot.at = static_cast<std::size_t>(s->line) - 1;
    slot.placement.index = s->index;
    slot.placement.before = s->text;
    slot.placement.before_is_unconditional = IsUnconditionalAction(*s);
    break;
  }
  if (slot.placement.before.empty()) {
    slot.placement.index = static_cast<int>(stmts.size()) + 1;
  }
  slot.at = SkipBackOverPrologue(lines, begin, slot.at);
  slot.placement.line = static_cast<int>(slot.at) + 1;
  return slot;
}

/// Common preamble: find the block, or say which zones exist.
auto LocateBlock(const Lines& lines, const PolicyView& view,
                 const std::string& zone)
    -> std::expected<std::size_t, std::string> {
  auto header = FindBlock(lines, zone);
  if (header != std::string::npos) return header;
  std::string list;
  for (const auto& z : view.zones) {
    if (!list.empty()) list += ", ";
    list += z;
  }
  return std::unexpected(std::format(
      "the policy has no `@xdp({})` block{}", zone,
      list.empty()
          ? " — it has no zone blocks at all"
          : std::format(" (it has: {})", list)));
}

/// Insert `block` at `slot`, followed by a blank line when the line it
/// lands in front of is not already blank.
auto InsertAt(Lines* lines, const Slot& slot, Lines block) -> void {
  if (slot.at < lines->size() && !(*lines)[slot.at].empty()) {
    block.push_back("");
  }
  lines->insert(lines->begin() + static_cast<long>(slot.at),
                block.begin(), block.end());
}

}  // namespace

auto AddRule(std::string_view document, const std::string& zone,
             const std::string& action, const RuleSpec& spec)
    -> std::expected<EditResult, std::string> {
  if (action != "allow" && action != "drop") {
    return std::unexpected(std::format(
        "'{}' is not an action — a rule is `allow` or `drop`",
        action));
  }
  if (auto why = spec.Refusal(); !why.empty()) {
    return std::unexpected(why);
  }
  auto lines = SplitLines(document);
  auto view = ReadPolicy(document);
  auto header = LocateBlock(lines, view, zone);
  if (!header) return std::unexpected(header.error());
  auto [begin, end] = BlockRange(lines, *header);

  auto statement = std::format("{} if {}", action, spec.Condition());
  // A rule already saying exactly this is not a change, and reporting
  // one would teach the operator that the verb writes duplicates.
  for (const auto* s : view.InZone(zone)) {
    if (s->text == statement) {
      return std::unexpected(std::format(
          "zone '{}' already has that rule, at position {}", zone,
          s->index));
    }
  }

  auto slot = EndOfGuardedRegion(lines, zone, begin, end, view);
  InsertAt(&lines, slot, {statement});
  EditResult out;
  out.document = Join(lines);
  out.placement = slot.placement;
  return out;
}

auto RemoveRule(std::string_view document, const std::string& zone,
                int index) -> std::expected<EditResult, std::string> {
  auto lines = SplitLines(document);
  auto view = ReadPolicy(document);
  auto header = LocateBlock(lines, view, zone);
  if (!header) return std::unexpected(header.error());
  auto stmts = view.InZone(zone);
  if (index < 1 || index > static_cast<int>(stmts.size())) {
    return std::unexpected(std::format(
        "zone '{}' has {} statement(s); there is no {}", zone,
        stmts.size(), index));
  }
  const auto* target = stmts[static_cast<std::size_t>(index) - 1];
  EditResult out;
  out.removed.push_back(target->text);

  // A `dnat` and a `redirect` sharing a guard are the two halves of
  // one port forward. Removing one of them is legal and is sometimes
  // what the operator means, but a `redirect` without its `dnat`
  // sends untranslated frames into the inside zone, so the survivor
  // is named rather than left to be discovered.
  if (target->verb == Verb::kTranslate ||
      target->verb == Verb::kRedirect) {
    auto guard = target->text.find(" if ");
    if (guard != std::string::npos) {
      auto cond = target->text.substr(guard);
      for (const auto* s : stmts) {
        if (s == target) continue;
        if (s->verb != Verb::kTranslate && s->verb != Verb::kRedirect) {
          continue;
        }
        if (s->verb == target->verb) continue;
        if (!s->text.ends_with(cond)) continue;
        out.warnings.push_back(std::format(
            "`{}` at position {} carries the same guard and is still "
            "there — the two are the halves of one port forward, and "
            "a redirect without its dnat sends untranslated frames "
            "into the inside zone. `no forward` removes both.",
            s->text, s->index));
      }
    }
  }

  auto at = static_cast<std::size_t>(target->line) - 1;
  lines.erase(lines.begin() + static_cast<long>(at),
              lines.begin() +
                  static_cast<long>(at + static_cast<std::size_t>(
                                             target->lines)));
  out.document = Join(lines);
  out.placement.index = index;
  out.placement.line = target->line;
  return out;
}

auto ForwardSpec::Refusal() const -> std::string {
  if (proto != "tcp" && proto != "udp") {
    return std::format(
        "'{}' cannot be forwarded — a port forward is tcp or udp",
        proto);
  }
  if (port < 1 || port > 65535) {
    return std::format("port {} is outside 1-65535", port);
  }
  if (target_port < 1 || target_port > 65535) {
    return std::format("target port {} is outside 1-65535",
                       target_port);
  }
  if (target_ip.empty()) return "no target address";
  if (inside_zone.empty()) return "no inside zone";
  return "";
}

auto ForwardSpec::Condition() const -> std::string {
  std::string out = std::format(
      "pkt.proto == {} and pkt.dst_port == {}", proto, port);
  if (!from.empty()) {
    out += std::format(
        " and pkt.src_ip {} {}",
        from.find('/') == std::string::npos ? "==" : "in", from);
  }
  return out;
}

auto AddForward(std::string_view document, const std::string& zone,
                const ForwardSpec& spec)
    -> std::expected<EditResult, std::string> {
  if (auto why = spec.Refusal(); !why.empty()) {
    return std::unexpected(why);
  }
  if (spec.inside_zone == zone) {
    return std::unexpected(std::format(
        "the target is in zone '{}', which is the zone the traffic "
        "arrives on — there is nothing to forward",
        zone));
  }
  auto lines = SplitLines(document);
  auto view = ReadPolicy(document);
  auto header = LocateBlock(lines, view, zone);
  if (!header) return std::unexpected(header.error());
  if (std::find(view.zones.begin(), view.zones.end(),
                spec.inside_zone) == view.zones.end()) {
    return std::unexpected(std::format(
        "the policy has no `@xdp({})` block, so a frame redirected "
        "there would arrive somewhere nothing inspects it",
        spec.inside_zone));
  }
  auto [begin, end] = BlockRange(lines, *header);

  const auto cond = spec.Condition();
  for (const auto* s : view.InZone(zone)) {
    if (s->verb == Verb::kTranslate && s->text.ends_with(cond)) {
      return std::unexpected(std::format(
          "zone '{}' already forwards {}/{}, at position {}", zone,
          spec.proto, spec.port, s->index));
    }
  }

  Lines block = {
      std::format("# {}/{} on this zone -> {}:{} in {}", spec.proto,
                  spec.port, spec.target_ip, spec.target_port,
                  spec.inside_zone),
      std::format("dnat to {}:{} if {}", spec.target_ip,
                  spec.target_port, cond),
      // The same guard, character for character. A redirect whose
      // guard is wider than its dnat's is the documented way to get
      // untranslated frames into the inside zone, and writing the
      // pair as one edit is how this verb makes that unreachable.
      std::format("redirect to {} if {}", spec.inside_zone, cond),
  };
  auto slot = TopOfGuardedRegion(lines, zone, begin, end, view);
  InsertAt(&lines, slot, block);
  EditResult out;
  out.document = Join(lines);
  out.placement = slot.placement;
  out.warnings.push_back(std::format(
      "this is a hole through the stateful rules below it: anything "
      "on {}/{} reaches {} whether or not the inside asked for it",
      spec.proto, spec.port, spec.target_ip));
  return out;
}

auto RemoveForward(std::string_view document, const std::string& zone,
                   const std::string& proto, int port)
    -> std::expected<EditResult, std::string> {
  auto lines = SplitLines(document);
  auto view = ReadPolicy(document);
  auto header = LocateBlock(lines, view, zone);
  if (!header) return std::unexpected(header.error());

  const auto needle =
      std::format("pkt.proto == {} and pkt.dst_port == {}", proto,
                  port);
  std::vector<const Statement*> hits;
  for (const auto* s : view.InZone(zone)) {
    if (s->verb != Verb::kTranslate && s->verb != Verb::kRedirect) {
      continue;
    }
    if (s->text.find(needle) == std::string::npos) continue;
    hits.push_back(s);
  }
  if (hits.empty()) {
    return std::unexpected(std::format(
        "zone '{}' forwards nothing on {}/{}", zone, proto, port));
  }

  EditResult out;
  bool saw_dnat = false;
  bool saw_redirect = false;
  for (const auto* s : hits) {
    out.removed.push_back(s->text);
    if (s->verb == Verb::kTranslate) saw_dnat = true;
    if (s->verb == Verb::kRedirect) saw_redirect = true;
  }
  // Erase from the bottom so the earlier line numbers stay valid.
  for (auto it = hits.rbegin(); it != hits.rend(); ++it) {
    auto at = static_cast<std::size_t>((*it)->line) - 1;
    lines.erase(lines.begin() + static_cast<long>(at),
                lines.begin() +
                    static_cast<long>(at + static_cast<std::size_t>(
                                               (*it)->lines)));
  }
  if (!saw_dnat) {
    out.warnings.push_back(
        "there was a `redirect` but no `dnat` — the forward was "
        "already half missing, and frames were reaching the inside "
        "zone untranslated");
  }
  if (!saw_redirect) {
    out.warnings.push_back(
        "there was a `dnat` but no `redirect` — the rewrite was "
        "happening and nothing was emitting the frame into the "
        "inside zone, so the forward was not working");
  }
  out.document = Join(lines);
  out.placement.index = hits.front()->index;
  out.placement.line = hits.front()->line;
  return out;
}

}  // namespace f::policy
