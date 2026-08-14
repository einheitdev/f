/// @file test_sysconfig_dns.cc
/// @brief The DNS setting whose failure mode is a name that is simply
///     not there.
///
/// `stop-dns-rebind` discards any upstream answer that points into
/// private address space. In an office every internal name — the file
/// server, the git server, the printer — is private-addressed *by
/// definition*, so the protection deletes exactly the answers the
/// people using the box need. The client sees an empty answer with no
/// error code; the only trace is one `possible DNS-rebind attack
/// detected` line in a journal nobody has a reason to be reading.
///
/// So the default is off, the artifact says which way it is set either
/// way, and turning it on without exempting a domain is a warning with
/// the consequence spelled out.

#include <gtest/gtest.h>

#include <string>

#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/validate.h"

namespace f::sysconfig {
namespace {

auto MustParse(const std::string& yaml) -> SystemConfig {
  auto parsed = ParseSystemConfigString(yaml);
  EXPECT_TRUE(parsed.has_value());
  return parsed.value_or(SystemConfig{});
}

constexpr const char* kBase = R"YAML(
zones:
  wan:
  testnet:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
)YAML";

auto Has(const std::string& hay, const std::string& needle) -> bool {
  return hay.find(needle) != std::string::npos;
}

auto CodeIn(const ValidationResult& r, const std::string& code)
    -> const Diagnostic* {
  for (const auto& d : r.diagnostics) {
    if (d.code == code) return &d;
  }
  return nullptr;
}

/// The product decision, pinned. An appliance that sits inside a
/// company resolves that company's names, and those names are private
/// by construction.
TEST(DnsRebindTest, ProtectionIsOffByDefault) {
  auto cfg = MustParse(kBase);
  ASSERT_EQ(cfg.dns.size(), 1u);
  EXPECT_FALSE(cfg.dns[0].stop_dns_rebind);
  auto plan = PlanDnsmasq(cfg);
  EXPECT_FALSE(plan.rebind_protection);
  EXPECT_FALSE(Has(plan.content, "\nstop-dns-rebind"));
}

/// Off is stated, not merely omitted. A line that is absent teaches
/// the reader nothing; the absence was the whole reason nobody found
/// this from the generated file.
TEST(DnsRebindTest, TheArtifactSaysWhichWayItIsSet) {
  auto off = PlanDnsmasq(MustParse(kBase));
  EXPECT_TRUE(Has(off.content, "rebind protection: OFF"))
      << off.content;

  auto on = PlanDnsmasq(MustParse(std::string(kBase) +
                                  "      stop_dns_rebind: true\n"));
  EXPECT_TRUE(Has(on.content, "rebind protection: ON"))
      << on.content;
  EXPECT_TRUE(Has(on.content, "\nstop-dns-rebind\n"));
  EXPECT_TRUE(on.rebind_protection);
}

/// Turning it on is legitimate for a zone that only ever resolves
/// public names, so the exemption list exists and reaches the daemon.
TEST(DnsRebindTest, ExemptDomainsReachTheArtifact) {
  auto plan = PlanDnsmasq(MustParse(
      std::string(kBase) +
      "      stop_dns_rebind: true\n"
      "      rebind_ok: [corp, internal.example]\n"));
  EXPECT_TRUE(Has(plan.content, "rebind-domain-ok=/corp/"))
      << plan.content;
  EXPECT_TRUE(
      Has(plan.content, "rebind-domain-ok=/internal.example/"));
  EXPECT_EQ(plan.rebind_exempt.size(), 2u);
}

/// Protection on with nothing exempted is the configuration that makes
/// every internal name in the building fail. It is allowed — and it is
/// never silent.
TEST(DnsRebindTest, ProtectionWithNoExemptionWarnsWithTheReason) {
  auto r = Validate(MustParse(std::string(kBase) +
                              "      stop_dns_rebind: true\n"));
  const auto* d = CodeIn(r, "SC045");
  ASSERT_NE(d, nullptr) << "turning this on silently is the defect";
  EXPECT_EQ(d->severity, Severity::kWarning);
  EXPECT_FALSE(r.HasErrors())
      << "a zone that resolves only public names may want this";
  EXPECT_TRUE(Has(d->hint, "rebind_ok")) << d->hint;
  EXPECT_TRUE(Has(d->message, "private address space"))
      << d->message;
}

TEST(DnsRebindTest, ExemptionsWithProtectionOffAreNotSilent) {
  auto r = Validate(
      MustParse(std::string(kBase) + "      rebind_ok: [corp]\n"));
  const auto* d = CodeIn(r, "SC046");
  ASSERT_NE(d, nullptr);
  EXPECT_EQ(d->severity, Severity::kWarning);
  EXPECT_FALSE(r.HasErrors());
}

TEST(DnsRebindTest, TheExemptedShapeIsClean) {
  auto r = Validate(MustParse(std::string(kBase) +
                              "      stop_dns_rebind: true\n"
                              "      rebind_ok: [corp]\n"));
  EXPECT_EQ(CodeIn(r, "SC045"), nullptr);
  EXPECT_EQ(CodeIn(r, "SC046"), nullptr);
  EXPECT_FALSE(r.HasErrors());
}

}  // namespace
}  // namespace f::sysconfig
