/// @file test_sysconfig_edit.cc
/// @brief `set address` edits the system configuration, in place.
///
/// The interesting property is not that the address lands — it is that
/// nothing else moves. An operator's comments are why the file is
/// readable at 18:00 with a serial console in one hand, so an edit
/// that eats them is a regression even though the model would still
/// validate.

#include <gtest/gtest.h>

#include <string>

#include "f/sysconfig/edit.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/parse.h"

namespace {

using f::sysconfig::AddressMode;
using f::sysconfig::ClearInterfaceAddress;
using f::sysconfig::InterfaceSeed;
using f::sysconfig::ParseSystemConfigString;
using f::sysconfig::SetInterfaceAddress;

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
)";

auto AddressOf(const std::string& doc, const std::string& iface)
    -> std::string {
  auto parsed = ParseSystemConfigString(doc);
  if (!parsed) return "<parse failed>";
  for (const auto& i : parsed->interfaces) {
    if (i.name == iface) {
      if (i.mode == AddressMode::kDhcpClient) return "dhcp";
      if (i.mode == AddressMode::kUnconfigured) return "none";
      return i.address;
    }
  }
  return "<absent>";
}

TEST(SysconfigEdit, ReplacesTheAddressAndNothingElse) {
  auto out = SetInterfaceAddress(kDoc, "lan0", "192.168.4.1/24");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(AddressOf(*out, "lan0"), "192.168.4.1/24");
  // Untouched neighbours.
  EXPECT_EQ(AddressOf(*out, "wan0"), "dhcp");
  EXPECT_NE(out->find("# the office-facing port"),
            std::string::npos);
  EXPECT_NE(out->find("# pinned to the port it was commissioned on"),
            std::string::npos);
  EXPECT_NE(out->find("zone: lan"), std::string::npos);
  EXPECT_EQ(out->find("10.10.0.1/24"), std::string::npos);
}

TEST(SysconfigEdit, DhcpAndNoneAreAddressesToo) {
  auto dhcp = SetInterfaceAddress(kDoc, "lan0", "dhcp");
  ASSERT_TRUE(dhcp.has_value()) << dhcp.error();
  EXPECT_EQ(AddressOf(*dhcp, "lan0"), "dhcp");

  auto cleared = ClearInterfaceAddress(kDoc, "lan0");
  ASSERT_TRUE(cleared.has_value()) << cleared.error();
  EXPECT_EQ(AddressOf(*cleared, "lan0"), "none");
  EXPECT_NE(cleared->find("zone: lan"), std::string::npos);
}

TEST(SysconfigEdit, AddsAnAddressKeyWhenThereIsNone) {
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    zone: lan\n";
  auto out = SetInterfaceAddress(doc, "lan0", "10.0.0.1/24");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(AddressOf(*out, "lan0"), "10.0.0.1/24");
  EXPECT_NE(out->find("zone: lan"), std::string::npos);
}

TEST(SysconfigEdit, DeclaresAnUndeclaredInterfaceWithItsIdentity) {
  InterfaceSeed seed{.mac = "52:54:00:aa:bb:09"};
  auto out = SetInterfaceAddress(kDoc, "dmz0", "10.9.0.1/24", seed);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(AddressOf(*out, "dmz0"), "10.9.0.1/24");
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  for (const auto& i : parsed->interfaces) {
    if (i.name == "dmz0") {
      EXPECT_EQ(i.match.value, "52:54:00:aa:bb:09")
          << "a name with no hardware identity survives nothing";
    }
  }
  // The interfaces already there are untouched.
  EXPECT_EQ(AddressOf(*out, "wan0"), "dhcp");
  EXPECT_EQ(AddressOf(*out, "lan0"), "10.10.0.1/24");
}

TEST(SysconfigEdit, RefusesToInventAnInterfaceWithoutIdentity) {
  auto out = SetInterfaceAddress(kDoc, "dmz0", "10.9.0.1/24");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("hardware address"), std::string::npos)
      << out.error();
}

TEST(SysconfigEdit, EditIsIdempotent) {
  auto once = SetInterfaceAddress(kDoc, "lan0", "192.168.4.1/24");
  ASSERT_TRUE(once.has_value());
  auto twice =
      SetInterfaceAddress(*once, "lan0", "192.168.4.1/24");
  ASSERT_TRUE(twice.has_value());
  EXPECT_EQ(*once, *twice);
}

// A document the parser rejects is not a document to edit.
TEST(SysconfigEdit, RefusesAnEditThatWouldNotParse) {
  const std::string doc =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    address: 10.0.0.1/24\n"
      "    nonsense: yes\n";
  auto out = SetInterfaceAddress(doc, "lan0", "10.0.0.2/24");
  EXPECT_FALSE(out.has_value());
}

TEST(SysconfigEdit, ClearRefusesAnUnknownInterface) {
  auto out = ClearInterfaceAddress(kDoc, "nope0");
  EXPECT_FALSE(out.has_value());
}

}  // namespace
