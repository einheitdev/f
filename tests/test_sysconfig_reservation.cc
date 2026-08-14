/// @file test_sysconfig_reservation.cc
/// @brief `set reservation` edits the system configuration, in place.
///
/// A reservation is the operator saying "this board keeps this
/// address". It has to land in the same document as the range it comes
/// out of, next to whatever he wrote about why — so these tests assert
/// the comments and the surrounding keys are still there afterwards,
/// not merely that the model parses.

#include <gtest/gtest.h>

#include <optional>
#include <string>

#include "f/sysconfig/edit.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/parse.h"

namespace {

using f::sysconfig::ClearDhcpReservation;
using f::sysconfig::ParseSystemConfigString;
using f::sysconfig::SetDhcpReservation;

constexpr const char* kDoc = R"(# the appliance
zones:
  wan:
  lan:

interfaces:
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
    # the bench segment
    - zone: lan
      range: 10.10.0.100-10.10.0.200
      lease: 12h
  dns:
    - zone: lan
)";

constexpr const char* kDocWithReservations = R"(zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: lan
services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
      reservations:
        # the reference board, do not move
        - mac: "aa:bb:cc:dd:ee:01"
          address: 10.10.0.10
          hostname: ref-board
        - mac: "aa:bb:cc:dd:ee:02"
          address: 10.10.0.11
)";

auto ReservationOf(const std::string& doc, const std::string& mac)
    -> std::optional<std::string> {
  auto parsed = ParseSystemConfigString(doc);
  if (!parsed) return "<parse failed>";
  for (const auto& d : parsed->dhcp) {
    for (const auto& r : d.reservations) {
      if (r.mac == mac) return r.address;
    }
  }
  return std::nullopt;
}

auto HostnameOf(const std::string& doc, const std::string& mac)
    -> std::string {
  auto parsed = ParseSystemConfigString(doc);
  if (!parsed) return "<parse failed>";
  for (const auto& d : parsed->dhcp) {
    for (const auto& r : d.reservations) {
      if (r.mac == mac) return r.hostname;
    }
  }
  return "<absent>";
}

TEST(Reservation, OpensAReservationsBlockWhenThereIsNone) {
  auto out = SetDhcpReservation(kDoc, "lan", "aa:bb:cc:dd:ee:01",
                                "10.10.0.10", "board-a");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(ReservationOf(*out, "aa:bb:cc:dd:ee:01"), "10.10.0.10");
  EXPECT_EQ(HostnameOf(*out, "aa:bb:cc:dd:ee:01"), "board-a");
}

TEST(Reservation, LeavesEveryOtherLineAlone) {
  auto out = SetDhcpReservation(kDoc, "lan", "aa:bb:cc:dd:ee:01",
                                "10.10.0.10", "board-a");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_NE(out->find("# the appliance"), std::string::npos);
  EXPECT_NE(out->find("# the bench segment"), std::string::npos);
  EXPECT_NE(out->find("range: 10.10.0.100-10.10.0.200"),
            std::string::npos);
  EXPECT_NE(out->find("lease: 12h"), std::string::npos);
  // The DNS service follows the DHCP one; a reservation appended to
  // the wrong block would take it with it.
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->dns.size(), 1U);
  EXPECT_EQ(parsed->dns[0].bind.zone, "lan");
}

TEST(Reservation, AppendsToAnExistingBlock) {
  auto out = SetDhcpReservation(kDocWithReservations, "lan",
                                "aa:bb:cc:dd:ee:03", "10.10.0.12", "");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->dhcp.size(), 1U);
  EXPECT_EQ(parsed->dhcp[0].reservations.size(), 3U);
  EXPECT_NE(out->find("# the reference board, do not move"),
            std::string::npos);
}

TEST(Reservation, ReaddressingKeepsTheCommentBesideIt) {
  auto out = SetDhcpReservation(kDocWithReservations, "lan",
                                "aa:bb:cc:dd:ee:01", "10.10.0.99", "");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(ReservationOf(*out, "aa:bb:cc:dd:ee:01"), "10.10.0.99");
  EXPECT_EQ(HostnameOf(*out, "aa:bb:cc:dd:ee:01"), "ref-board")
      << "re-addressing must not drop the name";
  EXPECT_NE(out->find("# the reference board, do not move"),
            std::string::npos);
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->dhcp[0].reservations.size(), 2U)
      << "an update is an update, not a second entry";
}

TEST(Reservation, AddsAHostnameToAnEntryThatHadNone) {
  auto out = SetDhcpReservation(kDocWithReservations, "lan",
                                "aa:bb:cc:dd:ee:02", "10.10.0.11",
                                "second-board");
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(HostnameOf(*out, "aa:bb:cc:dd:ee:02"), "second-board");
}

TEST(Reservation, MacSpellingDoesNotCreateADuplicate) {
  auto out = SetDhcpReservation(kDocWithReservations, "lan",
                                "AA:BB:CC:DD:EE:01", "10.10.0.77", "");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->dhcp[0].reservations.size(), 2U);
  EXPECT_EQ(ReservationOf(*out, "aa:bb:cc:dd:ee:01"), "10.10.0.77");
}

TEST(Reservation, RefusesAZoneWithNoDhcpServer) {
  auto out = SetDhcpReservation(kDoc, "wan", "aa:bb:cc:dd:ee:01",
                                "10.10.0.10", "");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("wan"), std::string::npos);
  EXPECT_NE(out.error().find("lan"), std::string::npos)
      << "say which zones do have one";
}

TEST(Reservation, RefusesToInventADhcpServer) {
  constexpr const char* kNoServices = R"(zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: lan
)";
  auto out = SetDhcpReservation(kNoServices, "lan",
                                "aa:bb:cc:dd:ee:01", "10.10.0.10", "");
  ASSERT_FALSE(out.has_value());
}

TEST(Reservation, RefusesSomethingThatIsNotAMac) {
  auto out = SetDhcpReservation(kDoc, "lan", "10.10.0.10",
                                "10.10.0.10", "");
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("MAC"), std::string::npos);
}

TEST(Reservation, RefusesSomethingThatIsNotAnAddress) {
  auto out = SetDhcpReservation(kDoc, "lan", "aa:bb:cc:dd:ee:01",
                                "not-an-address", "");
  ASSERT_FALSE(out.has_value());
}

TEST(Reservation, RemovingOneLeavesTheOthers) {
  auto out = ClearDhcpReservation(kDocWithReservations,
                                  "aa:bb:cc:dd:ee:01");
  ASSERT_TRUE(out.has_value()) << out.error();
  auto parsed = ParseSystemConfigString(*out);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->dhcp.size(), 1U);
  EXPECT_EQ(parsed->dhcp[0].reservations.size(), 1U);
  EXPECT_EQ(parsed->dhcp[0].reservations[0].mac,
            "aa:bb:cc:dd:ee:02");
}

TEST(Reservation, RemovingTheLastOneTakesTheEmptyKeyWithIt) {
  auto once = ClearDhcpReservation(kDocWithReservations,
                                   "aa:bb:cc:dd:ee:01");
  ASSERT_TRUE(once.has_value()) << once.error();
  auto twice = ClearDhcpReservation(*once, "aa:bb:cc:dd:ee:02");
  ASSERT_TRUE(twice.has_value()) << twice.error();
  EXPECT_EQ(twice->find("reservations:"), std::string::npos);
  auto parsed = ParseSystemConfigString(*twice);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->dhcp.size(), 1U);
  EXPECT_TRUE(parsed->dhcp[0].reservations.empty());
  EXPECT_EQ(parsed->dhcp[0].range_start, "10.10.0.100");
}

TEST(Reservation, RemovingOneThatIsNotThereIsAnError) {
  auto out = ClearDhcpReservation(kDocWithReservations,
                                  "aa:bb:cc:dd:ee:ff");
  ASSERT_FALSE(out.has_value())
      << "a MAC typed by hand that matches nothing must say so";
}

TEST(Reservation, TheEditIsReparsedBeforeItIsReturned) {
  // A document whose dhcp entry is malformed enough that any edit
  // would produce something the model refuses. The edit must not hand
  // that back to a caller who is about to install it.
  constexpr const char* kBroken = R"(zones:
  lan:
services:
  dhcp:
    - zone: lan
)";
  auto out = SetDhcpReservation(kBroken, "lan", "aa:bb:cc:dd:ee:01",
                                "10.10.0.10", "");
  ASSERT_FALSE(out.has_value())
      << "the range is missing, so the edited document does not "
         "validate and is refused";
}

}  // namespace
