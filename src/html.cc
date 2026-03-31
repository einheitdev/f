/// @file html.cc
/// @brief HTML fragment rendering for HTMX endpoints.

#include "f/html.h"

#include <arpa/inet.h>

#include <format>

#include "f/engine.h"

namespace f {

auto Html::Tag(std::string_view tag, std::string_view attrs,
               std::string_view body) -> Html& {
  if (attrs.empty()) {
    std::format_to(std::back_inserter(buf),
                   "<{}>{}</{}>", tag, body, tag);
  } else {
    std::format_to(std::back_inserter(buf),
                   "<{} {}>{}</{}>", tag, attrs, body, tag);
  }
  return *this;
}

auto Html::Raw(std::string_view s) -> Html& {
  buf.append(s);
  return *this;
}

auto Html::Build() -> std::string {
  return std::move(buf);
}

namespace {

auto IpStr(uint32_t addr) -> std::string {
  char buf[INET_ADDRSTRLEN];
  struct in_addr in;
  in.s_addr = addr;
  inet_ntop(AF_INET, &in, buf, sizeof(buf));
  return buf;
}

auto ActionStr(uint8_t a) -> std::string_view {
  switch (a) {
    case 0: return "DROP";
    case 1: return "ALLOW";
    case 2: return "RATE_LIMIT";
    default: return "?";
  }
}

auto ProtoStr(uint8_t p) -> std::string_view {
  switch (p) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMP";
    case 0: return "ANY";
    default: return "?";
  }
}

}  // namespace

auto RenderStatusCard(const StatusResponse& s)
    -> std::string {
  return std::format(
      R"(<div class="status-grid">)"
      R"(<div class="status-item">)"
      R"(<span class="status-label">PID</span>)"
      R"(<span class="status-value">{}</span></div>)"
      R"(<div class="status-item">)"
      R"(<span class="status-label">Uptime</span>)"
      R"(<span class="status-value">{}s</span></div>)"
      R"(<div class="status-item">)"
      R"(<span class="status-label">Active Table</span>)"
      R"(<span class="status-value">{}</span></div>)"
      R"(<div class="status-item">)"
      R"(<span class="status-label">Rules</span>)"
      R"(<span class="status-value">{}</span></div>)"
      R"(<div class="status-item">)"
      R"(<span class="status-label">Interfaces</span>)"
      R"(<span class="status-value">{}</span></div>)"
      R"(</div>)",
      s.pid, s.uptime_s,
      s.active_table == 0 ? "A" : "B",
      s.rule_count, s.iface_count);
}

auto RenderRulesTable(
    std::span<const std::pair<RuleKey, RuleValue>> rules)
    -> std::string {
  if (rules.empty()) {
    return R"(<div class="empty">No rules configured.</div>)";
  }
  Html h;
  h.Raw(R"(<table><thead><tr>)"
        R"(<th>Src</th><th>Dst</th><th>Proto</th>)"
        R"(<th>SPort</th><th>DPort</th><th>Action</th>)"
        R"(<th></th>)"
        R"(</tr></thead><tbody>)");
  for (size_t i = 0; i < rules.size(); i++) {
    const auto& [k, v] = rules[i];
    h.Raw(std::format(
        R"(<tr><td>{}</td><td>{}</td><td>{}</td>)"
        R"(<td class="mono">{}</td>)"
        R"(<td class="mono">{}</td>)"
        R"(<td>{}</td>)"
        R"(<td><button class="btn-danger" )"
        R"(hx-delete="/api/v1/rules/{}" )"
        R"(hx-target="closest table" )"
        R"(hx-swap="outerHTML">Del</button></td></tr>)",
        IpStr(k.src_addr), IpStr(k.dst_addr),
        ProtoStr(k.proto), k.src_port, k.dst_port,
        ActionStr(v.action), i));
  }
  h.Raw("</tbody></table>");
  return h.Build();
}

auto RenderCountersTable(
    std::span<const RuleCounter> counters)
    -> std::string {
  if (counters.empty()) {
    return R"(<div class="empty">No counters.</div>)";
  }
  Html h;
  h.Raw(R"(<table><thead><tr>)"
        R"(<th>Rule</th>)"
        R"(<th class="right">Packets</th>)"
        R"(<th class="right">Bytes</th>)"
        R"(</tr></thead><tbody>)");
  for (size_t i = 0; i < counters.size(); i++) {
    h.Raw(std::format(
        R"(<tr><td>{}</td>)"
        R"(<td class="right mono">{}</td>)"
        R"(<td class="right mono">{}</td></tr>)",
        i, counters[i].packets, counters[i].bytes));
  }
  h.Raw("</tbody></table>");
  return h.Build();
}

auto RenderConntrackTable(
    std::span<const std::pair<ConnKey, ConnValue>> conns)
    -> std::string {
  if (conns.empty()) {
    return R"(<div class="empty">No connections.</div>)";
  }
  Html h;
  h.Raw(R"(<table><thead><tr>)"
        R"(<th>Source</th><th>Destination</th>)"
        R"(<th>Proto</th><th class="right">Packets</th>)"
        R"(<th>State</th>)"
        R"(</tr></thead><tbody>)");
  for (const auto& [k, v] : conns) {
    h.Raw(std::format(
        R"(<tr><td>{}:{}</td><td>{}:{}</td>)"
        R"(<td>{}</td>)"
        R"(<td class="right mono">{}</td>)"
        R"(<td>{}</td></tr>)",
        IpStr(k.src_addr), k.src_port,
        IpStr(k.dst_addr), k.dst_port,
        ProtoStr(k.proto), v.packets,
        v.state == 1 ? "ESTABLISHED" : "NEW"));
  }
  h.Raw("</tbody></table>");
  return h.Build();
}

auto RenderInterfaceList(
    std::span<const IfAttach> ifaces)
    -> std::string {
  if (ifaces.empty()) {
    return R"(<div class="empty">No interfaces attached.</div>)";
  }
  Html h;
  for (const auto& iface : ifaces) {
    h.Raw(std::format(
        R"(<div class="iface-item">)"
        R"(<div><span class="iface-name">{}</span>)"
        R"(<span class="iface-idx">ifindex={}</span>)"
        R"(</div>)"
        R"(<span class="badge badge-green">)"
        R"(attached</span></div>)",
        iface.name, iface.ifindex));
  }
  return h.Build();
}

auto RenderLogEntries(
    std::span<const LogEntry> entries)
    -> std::string {
  if (entries.empty()) {
    return R"(<div class="empty">No log entries.</div>)";
  }
  Html h;
  h.Raw(R"(<div class="log-scroll">)");
  // Reverse order — newest first.
  for (auto it = entries.rbegin();
       it != entries.rend(); ++it) {
    const auto& e = *it;
    std::string_view cls = "log-info";
    if (e.level == "error" || e.level == "critical") {
      cls = "log-error";
    } else if (e.level == "warn" ||
               e.level == "warning") {
      cls = "log-warn";
    } else if (e.level == "debug" ||
               e.level == "trace") {
      cls = "log-debug";
    }
    h.Raw(std::format(
        R"(<div class="log-entry">)"
        R"(<span class="log-ts">{}</span> )"
        R"(<span class="log-lvl {}">[{}]</span> )"
        R"({}</div>)",
        e.timestamp, cls, e.level, e.message));
  }
  h.Raw("</div>");
  return h.Build();
}

}  // namespace f
