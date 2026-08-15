/// @file test_sysconfig_zone_edit.cc
/// @brief `set zone` / `set interface zone` edit the system config.
///
/// Until these existed, firstboot was the only thing on a box that
/// ever *wrote* a zone, and everything after commissioning was an
/// operator with a text editor. The assertions here are the two that
/// make the verbs worth having: the edit lands in the one document
/// the model reads, and the surrounding file — comments, ordering,
/// the other zones — is exactly where it was.
///
/// The refusals matter as much as the edits. A zone name is not
/// created by being referenced, and a zone is not deleted out from
/// under the interfaces and services still pointing at it.

#include <gtest/gtest.h>

#include <string>

#include "f/sysconfig/edit.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/parse.h"

namespace {

using f::sysconfig::ClearDhcpServer;
using f::sysconfig::ClearDnsForwarder;
using f::sysconfig::ClearInterfaceZone;
using f::sysconfig::ClearZone;
using f::sysconfig::InterfaceSeed;
using f::sysconfig::Ipv6Stance;
using f::sysconfig::ParseSystemConfigString;
using f::sysconfig::SetDhcpServer;
using f::sysconfig::SetDnsForwarder;
using f::sysconfig::SetInterfaceZone;
using f::sysconfig::SetZone;

constexpr const char* kDoc = R"(# the appliance
zones:
  # the office-facing port
  wan:
  lan:

interfaces:
  # pinned to the port it was commissioned on
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan

  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: lan

services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
)";

auto ZoneOf(const std::string& doc, const std::string& iface)
    -> std::string {
  auto parsed = ParseSystemConfigString(doc);
  if (!parsed) return "<parse failed>";
  const auto* i = parsed->FindInterface(iface);
  if (i == nullptr) return "<absent>";
  return i->zone.empty() ? "(none)" : i->zone;
}

auto HasZone(const std::string& doc, const std::string& zone)
    -> bool {
  auto parsed = ParseSystemConfigString(doc);
  if (!parsed) return false;
  return parsed->FindZone(zone) != nullptr;
}

TEST(SysconfigZoneEdit, DeclaresANewZone) {
  auto out = SetZone(kDoc, "dmz");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_TRUE(HasZone(*out, "dmz"));
  // The zones that were there are still there, and so is the comment
  // that explains one of them.
  EXPECT_TRUE(HasZone(*out, "wan"));
  EXPECT_TRUE(HasZone(*out, "lan"));
  EXPECT_NE(out->find("# the office-facing port"), std::string::npos);
  EXPECT_NE(out->find("# the appliance"), std::string::npos);
}

// A zone with nothing in it is the normal first state of a new
// segment: you declare it, then you move a port into it. Refusing it
// would make the two-step impossible and force the editor back.
TEST(SysconfigZoneEdit, ANewZoneMayBeEmpty) {
  auto out = SetZone(kDoc, "dmz");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->InterfacesInZone("dmz").empty());
}

TEST(SysconfigZoneEdit, DeclaresAZoneWithAStance) {
  auto out = SetZone(kDoc, "dmz", "ra");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  const auto* z = parsed->FindZone("dmz");
  ASSERT_NE(z, nullptr);
  EXPECT_EQ(z->ipv6, Ipv6Stance::kRouterAdvertise);
}

TEST(SysconfigZoneEdit, ChangesTheStanceOfAnExistingZone) {
  auto out = SetZone(kDoc, "wan", "ra");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  const auto* z = parsed->FindZone("wan");
  ASSERT_NE(z, nullptr);
  EXPECT_EQ(z->ipv6, Ipv6Stance::kRouterAdvertise);
  // ...and does not disturb the interface that lives in it.
  EXPECT_EQ(ZoneOf(*out, "wan0"), "wan");
}

// Re-declaring a zone with nothing to change is a no-op the operator
// should hear about, not a silent success that implies something
// happened.
TEST(SysconfigZoneEdit, RefusesToRedeclareAZoneWithNoChange) {
  auto out = SetZone(kDoc, "lan");
  EXPECT_FALSE(out.has_value());
}

TEST(SysconfigZoneEdit, RefusesAnUnknownStance) {
  auto out = SetZone(kDoc, "dmz", "maybe");
  EXPECT_FALSE(out.has_value());
}

TEST(SysconfigZoneEdit, OpensTheZonesSectionWhenThereIsNone) {
  const std::string doc =
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n";
  auto out = SetZone(doc, "lan");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_TRUE(HasZone(*out, "lan"));
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_NE(parsed->FindInterface("lan0"), nullptr);
}

// The whole point of a declared zone list is that a typo fails at the
// edit rather than producing a second, empty segment that quietly
// carries no service and no policy.
TEST(SysconfigZoneEdit, RefusesToPutAnInterfaceInAnUndeclaredZone) {
  auto out = SetInterfaceZone(kDoc, "lan0", "dmzz");
  ASSERT_FALSE(out.has_value());
  // ...and names the zones that do exist, so the typo is visible.
  EXPECT_NE(out.error().find("wan"), std::string::npos);
  EXPECT_NE(out.error().find("lan"), std::string::npos);
}

TEST(SysconfigZoneEdit, MovesAnInterfaceBetweenZones) {
  auto with_dmz = SetZone(kDoc, "dmz");
  ASSERT_TRUE(with_dmz.has_value()) << with_dmz.error();
  auto out = SetInterfaceZone(*with_dmz, "lan0", "dmz");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(ZoneOf(*out, "lan0"), "dmz");
  // The other port did not move with it.
  EXPECT_EQ(ZoneOf(*out, "wan0"), "wan");
  // And the address it carries is untouched: a zone move is not an
  // addressing change.
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->FindInterface("lan0")->address, "10.10.0.1/24");
}

TEST(SysconfigZoneEdit, DeclaresAnInterfaceItHasNotSeenBefore) {
  InterfaceSeed seed;
  seed.mac = "52:54:00:aa:bb:09";
  auto out = SetInterfaceZone(kDoc, "dmz0", "lan", seed);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(ZoneOf(*out, "dmz0"), "lan");
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->FindInterface("dmz0")->match.value,
            "52:54:00:aa:bb:09");
}

// A name with no hardware identity behind it survives nothing, which
// is what the model refuses; the edit refuses it too rather than
// writing a declaration that the next validation will reject.
TEST(SysconfigZoneEdit, RefusesAnUndeclaredInterfaceWithNoIdentity) {
  auto out = SetInterfaceZone(kDoc, "dmz0", "lan");
  EXPECT_FALSE(out.has_value());
}

TEST(SysconfigZoneEdit, TakesAnInterfaceOutOfItsZone) {
  auto out = ClearInterfaceZone(kDoc, "wan0");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(ZoneOf(*out, "wan0"), "(none)");
  // Still declared, still pinned, still addressed.
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_NE(parsed->FindInterface("wan0"), nullptr);
  EXPECT_EQ(parsed->FindInterface("wan0")->match.value,
            "52:54:00:aa:bb:01");
}

TEST(SysconfigZoneEdit, ClearRefusesAnUnknownInterface) {
  auto out = ClearInterfaceZone(kDoc, "nope0");
  EXPECT_FALSE(out.has_value());
}

// Deleting a zone that something still points at would leave a
// document naming a zone it does not declare, and the operator would
// hear about it as a validation error about the *service*.
TEST(SysconfigZoneEdit, RefusesToDeleteAZoneAnInterfaceIsIn) {
  auto out = ClearZone(kDoc, "wan");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("wan0"), std::string::npos);
}

TEST(SysconfigZoneEdit, RefusesToDeleteAZoneAServiceIsBoundTo) {
  auto emptied = ClearInterfaceZone(kDoc, "lan0");
  ASSERT_TRUE(emptied.has_value()) << emptied.error();
  auto out = ClearZone(*emptied, "lan");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("DHCP"), std::string::npos);
}

TEST(SysconfigZoneEdit, DeletesAZoneNothingPointsAt) {
  auto with_dmz = SetZone(kDoc, "dmz");
  ASSERT_TRUE(with_dmz.has_value()) << with_dmz.error();
  auto out = ClearZone(*with_dmz, "dmz");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_FALSE(HasZone(*out, "dmz"));
  EXPECT_TRUE(HasZone(*out, "wan"));
  EXPECT_TRUE(HasZone(*out, "lan"));
}

TEST(SysconfigZoneEdit, RefusesToDeleteAZoneThatIsNotThere) {
  auto out = ClearZone(kDoc, "dmz");
  EXPECT_FALSE(out.has_value());
}

// The last zone takes the `zones:` key with it: an empty key parses
// as null and reads as an unfinished edit.
TEST(SysconfigZoneEdit, TheLastZoneTakesTheKeyWithIt) {
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n";
  auto out = ClearZone(doc, "lan");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(out->find("zones:"), std::string::npos);
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->zones.empty());
  EXPECT_NE(parsed->FindInterface("lan0"), nullptr);
}

// -- services ---------------------------------------------------------
//
// A service names a zone and nothing else that decides placement, so
// there is no interface argument to these edits and there cannot be
// one. That is the whole reason "DHCP answers on the uplink" is a
// sentence the model has no words for.

TEST(SysconfigServiceEdit, DeclaresADhcpServerOnAZone) {
  auto with_dmz = SetZone(kDoc, "dmz");
  ASSERT_TRUE(with_dmz.has_value()) << with_dmz.error();
  auto out = SetDhcpServer(*with_dmz, "dmz", "10.20.0.100",
                           "10.20.0.200", "6h");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  bool found = false;
  for (const auto& d : parsed->dhcp) {
    if (d.bind.zone != "dmz") continue;
    found = true;
    EXPECT_EQ(d.range_start, "10.20.0.100");
    EXPECT_EQ(d.range_end, "10.20.0.200");
    EXPECT_EQ(d.lease_seconds, 6u * 3600u);
  }
  EXPECT_TRUE(found);
  // The server that was already there is untouched.
  EXPECT_TRUE(parsed->ZoneServesDhcp("lan"));
}

TEST(SysconfigServiceEdit, OpensTheServicesSectionWhenThereIsNone) {
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    address: 10.10.0.1/24\n"
      "    zone: lan\n";
  auto out =
      SetDhcpServer(doc, "lan", "10.10.0.100", "10.10.0.200", "12h");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->ZoneServesDhcp("lan"));
}

/// The shape firstboot ACTUALLY writes, and it broke every service
/// verb on every factory box.
///
/// `services: {}` is an empty FLOW mapping. `OpenServiceSequence`
/// found the top-level key, found no child under it — correctly,
/// there is no block — and appended `  dhcp:` on the next line, which
/// produces
///
///     services: {}
///       dhcp:
///         - zone: lan
///
/// and that is not YAML. The command refused with `the edit would not
/// parse (error[SC100]: 51:3: yaml parse: end of map not found) —
/// nothing was changed`, which is the guard working and also a
/// message that names neither the cause nor anything the operator
/// can do. Measured on a booted image: a box that had just
/// provisioned itself, split into zones through `set interface zone`,
/// could not then be given a DHCP server or a resolver through the
/// CLI at all. `OpensTheServicesSectionWhenThereIsNone` passed
/// throughout, because it uses a document with no `services:` line —
/// the one shape a factory box never has.
TEST(SysconfigServiceEdit, OpensAnEmptyFlowServicesMap) {
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    address: 10.10.0.1/24\n"
      "    zone: lan\n"
      "\n"
      "# No service is bound to any zone.\n"
      "services: {}\n";
  auto out =
      SetDhcpServer(doc, "lan", "10.10.0.100", "10.10.0.200", "12h");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->ZoneServesDhcp("lan"));
  // The comment above it is why the file is readable at 18:00 with a
  // serial console in one hand.
  EXPECT_NE(out->find("# No service is bound to any zone."),
            std::string::npos);
  // ...and the flow marker is gone rather than left beside a block
  // that now says something different.
  EXPECT_EQ(out->find("services: {}"), std::string::npos) << *out;
}

TEST(SysconfigServiceEdit, OpensAnEmptyFlowServicesMapForDns) {
  // The same document and the other verb, because the two reach
  // `OpenServiceSequence` by different callers and a fix in one is
  // not a fix in the other.
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    address: 10.10.0.1/24\n"
      "    zone: lan\n"
      "services: {}\n";
  auto out = SetDnsForwarder(doc, "lan", {"10.10.2.2"});
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->ZoneServesDns("lan"));
}

/// An empty flow SEQUENCE looks like the same mistake and is not one:
/// `services` must be a MAP, so `services: []` is a document the
/// model refuses before any edit is attempted. Pinned so that nobody
/// "fixes" it in `OpenServiceSequence`, where the code would be
/// unreachable and would read as cover.
TEST(SysconfigServiceEdit, AnEmptyFlowSequenceIsRefusedByTheModel) {
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    address: 10.10.0.1/24\n"
      "    zone: lan\n"
      "services: []\n";
  auto out =
      SetDhcpServer(doc, "lan", "10.10.0.100", "10.10.0.200", "12h");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("SC102"), std::string::npos)
      << out.error();
}

/// A NON-empty inline value is a document this editor cannot extend
/// without guessing, and it must say so rather than produce the same
/// unparseable file with a different cause.
TEST(SysconfigServiceEdit, RefusesAServicesMapWrittenInline) {
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    address: 10.10.0.1/24\n"
      "    zone: lan\n"
      "services: {dns: [{zone: lan}]}\n";
  auto out =
      SetDhcpServer(doc, "lan", "10.10.0.100", "10.10.0.200", "12h");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("services"), std::string::npos)
      << out.error();
  EXPECT_NE(out.error().find("one key per line"), std::string::npos)
      << out.error();
}

TEST(SysconfigServiceEdit, ReRangesAnExistingServer) {
  auto out = SetDhcpServer(kDoc, "lan", "10.10.0.50", "10.10.0.60");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  int servers = 0;
  for (const auto& d : parsed->dhcp) {
    if (d.bind.zone != "lan") continue;
    ++servers;
    EXPECT_EQ(d.range_start, "10.10.0.50");
  }
  // One DHCP server per zone (SC023). Re-ranging must not add one.
  EXPECT_EQ(servers, 1);
}

// A service binds to a zone, so the zone comes first. Hearing it here
// beats hearing it from `Validate` about the service you were just
// told had been created.
TEST(SysconfigServiceEdit, RefusesAZoneThatIsNotDeclared) {
  auto out =
      SetDhcpServer(kDoc, "nope", "10.30.0.100", "10.30.0.200");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("lan"), std::string::npos);
}

TEST(SysconfigServiceEdit, RefusesARangeThatIsNotAddresses) {
  auto out = SetDhcpServer(kDoc, "lan", "ten", "twenty");
  EXPECT_FALSE(out.has_value());
}

TEST(SysconfigServiceEdit, RemovesADhcpServerAndItsReservations) {
  auto out = ClearDhcpServer(kDoc, "lan");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_FALSE(parsed->ZoneServesDhcp("lan"));
  // The zone survives the service; they are different statements.
  EXPECT_NE(parsed->FindZone("lan"), nullptr);
}

TEST(SysconfigServiceEdit, RefusesToRemoveOneThatIsNotThere) {
  auto out = ClearDhcpServer(kDoc, "wan");
  EXPECT_FALSE(out.has_value());
}

TEST(SysconfigServiceEdit, DeclaresADnsForwarder) {
  auto out = SetDnsForwarder(kDoc, "lan", {"9.9.9.9", "1.1.1.1"});
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->dns.size(), 1u);
  EXPECT_EQ(parsed->dns[0].bind.zone, "lan");
  ASSERT_EQ(parsed->dns[0].upstreams.size(), 2u);
  EXPECT_EQ(parsed->dns[0].upstreams[0], "9.9.9.9");
}

// No upstream is a real answer — inherit the system resolver — and it
// is not the same as no forwarder.
TEST(SysconfigServiceEdit, ADnsForwarderMayHaveNoUpstream) {
  auto out = SetDnsForwarder(kDoc, "lan", {});
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->dns.size(), 1u);
  EXPECT_TRUE(parsed->dns[0].upstreams.empty());
}

TEST(SysconfigServiceEdit, RepointsAnExistingForwarder) {
  auto first = SetDnsForwarder(kDoc, "lan", {"9.9.9.9"});
  ASSERT_TRUE(first.has_value()) << first.error();
  auto out = SetDnsForwarder(*first, "lan", {"1.1.1.1"});
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->dns.size(), 1u);
  ASSERT_EQ(parsed->dns[0].upstreams.size(), 1u);
  EXPECT_EQ(parsed->dns[0].upstreams[0], "1.1.1.1");
}

TEST(SysconfigServiceEdit, RemovesADnsForwarder) {
  auto first = SetDnsForwarder(kDoc, "lan", {"9.9.9.9"});
  ASSERT_TRUE(first.has_value()) << first.error();
  auto out = ClearDnsForwarder(*first, "lan");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->dns.empty());
}

// The document these verbs write is the same document a person
// writes, and a zone still holding a service cannot be deleted
// however the service got there.
TEST(SysconfigServiceEdit, AZoneServingDhcpStillCannotBeDeleted) {
  auto with_dmz = SetZone(kDoc, "dmz");
  ASSERT_TRUE(with_dmz.has_value()) << with_dmz.error();
  auto served = SetDhcpServer(*with_dmz, "dmz", "10.20.0.100",
                              "10.20.0.200");
  ASSERT_TRUE(served.has_value()) << served.error();
  auto out = ClearZone(*served, "dmz");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("DHCP"), std::string::npos);
}

}  // namespace
