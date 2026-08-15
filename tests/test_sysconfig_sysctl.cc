/// @file test_sysconfig_sysctl.cc
/// @brief The forwarding sysctl: generated, installed, and APPLIED.
///
/// The finding these exist for: nothing in `f` set or mentioned
/// `net.ipv4.ip_forward` anywhere — not the networkd generator, not the
/// units, not the deployment guide, not the handbook. A firewall
/// appliance that routes between zones cannot pass a packet without it,
/// and Linux says so twice: the stack refuses to forward, and
/// `bpf_fib_lookup` — the helper the XDP redirect uses to learn the
/// next hop's MAC — answers BPF_FIB_LKUP_RET_FWD_DISABLED, so the
/// datapath silently degrades to forwarding frames with the destination
/// MAC they arrived carrying.
///
/// The half these tests used to be about was `applied` — a drop-in on
/// disk that nobody has read is a box that forwards after the next
/// reboot and not now. That is no longer what this artifact does, and
/// the reversal is the thing under test now: the planned value is 0,
/// the drop-in is the BOOT-TIME FLOOR, and the live knob belongs to
/// `fd`, which raises it only while a compiled bundle is in the packet
/// path. See `f/sysconfig/sysctl.h` for the measurement that decided
/// it and `f/route_mgr.h` for the invariant.

#include <filesystem>
#include <fstream>
#include <random>
#include <string>

#include <gtest/gtest.h>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/sysctl.h"

namespace f::sysconfig {
namespace {

constexpr const char* kGatewayShape = R"YAML(
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
)YAML";

auto Read(const std::filesystem::path& p) -> std::string {
  std::ifstream in(p);
  return {std::istreambuf_iterator<char>(in),
          std::istreambuf_iterator<char>()};
}

class SysctlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::random_device rd;
    root_ = std::filesystem::temp_directory_path() /
            ("f-sysctl-" + std::to_string(rd()));
    std::filesystem::create_directories(root_);
    auto parsed = ParseSystemConfigString(kGatewayShape);
    ASSERT_TRUE(parsed.has_value());
    cfg_ = *parsed;
    opts_.dir = (root_ / "sysctl.d").string();
    opts_.proc_dir = (root_ / "proc-sys").string();
  }
  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }

  auto LivePath() const -> std::filesystem::path {
    return root_ / "proc-sys" / "net" / "ipv4" / "ip_forward";
  }

  std::filesystem::path root_;
  SystemConfig cfg_;
  SysctlOptions opts_;
};

/// The reversal, in one assertion. This planned 1 unconditionally
/// until a provisioned box with its bundle removed was measured
/// forwarding un-masqueraded traffic while `fd` refused to start and
/// said so in the journal. A box that does not forward is a visible
/// fault; a box that forwards unfiltered is an invisible one.
TEST_F(SysctlTest, TheBootTimeFloorIsClosed) {
  auto values = PlanSysctlValues(cfg_);
  ASSERT_EQ(values.size(), 1U);
  EXPECT_EQ(values[0].first, "net.ipv4.ip_forward");
  EXPECT_EQ(values[0].second, "0");
}

/// Still not derived from the zone count — that derivation was
/// rejected for creating a second way to be silently non-routing and
/// it is still rejected. What replaced the unconditional 1 is not a
/// cleverer plan here; it is `fd` setting the LIVE value from a fact
/// it establishes rather than infers (how many interfaces the kernel
/// accepted an XDP program on). This file plans the same floor for
/// every shape of box.
TEST_F(SysctlTest, TheFloorIsNotConditionalOnTheZoneCount) {
  auto bare = ParseSystemConfigString(
      "zones:\n  wan:\n\ninterfaces:\n  wan0:\n"
      "    mac: \"52:54:00:aa:bb:01\"\n    address: dhcp\n"
      "    zone: wan\n");
  ASSERT_TRUE(bare.has_value());
  auto values = PlanSysctlValues(*bare);
  ASSERT_EQ(values.size(), 1U);
  EXPECT_EQ(values[0].second, "0");
}

TEST_F(SysctlTest, TheDropInIsADerivedArtifactLikeEveryOther) {
  auto unit = PlanSysctl(cfg_, opts_);
  EXPECT_EQ(unit.path, (root_ / "sysctl.d" / "10-f-forwarding.conf"));
  EXPECT_NE(unit.content.find("net.ipv4.ip_forward = 0"),
            std::string::npos);
  // The file has to say what it is, because an operator who finds a
  // box passing no traffic WILL find this file and WILL try setting
  // it to 1. It tells them where the real answer is instead.
  EXPECT_NE(unit.content.find("BOOT-TIME FLOOR"), std::string::npos);
  EXPECT_NE(unit.content.find("einheit-f show status"),
            std::string::npos);
  // Nothing on disk yet, so the drift kind is kAbsent — not kNone,
  // which would say "identical to the model".
  EXPECT_EQ(CheckSysctlDrift(unit), DriftKind::kAbsent);
}

/// Installs the file and touches NO kernel knob, and that is the
/// second half of the reversal.
///
/// It used to write both, on the reasoning that a drop-in nobody
/// applies until the next reboot is the same silent failure with a
/// longer fuse. That was right while this file decided whether the
/// box forwards. Now that the floor is 0, pushing it into a RUNNING
/// kernel would stop a healthy filtering box from routing — and fd
/// deliberately does not fight a lowered knob, so it would stay
/// stopped. `apply system` is what an operator runs to change a DNS
/// server; it must not be able to take the office offline.
TEST_F(SysctlTest, ApplyInstallsTheFileAndTouchesNoLiveKnob) {
  auto r = ApplySysctl(cfg_, opts_);
  ASSERT_TRUE(r.has_value()) << (r ? "" : r.error());
  EXPECT_TRUE(r->changed);
  EXPECT_TRUE(std::filesystem::exists(r->unit.path));
  EXPECT_TRUE(r->applied.empty());
  EXPECT_FALSE(std::filesystem::exists(LivePath()));
}

/// The case that names the danger directly: a box that IS forwarding,
/// because fd armed it, must still be forwarding after an unrelated
/// `apply system`.
TEST_F(SysctlTest, ApplyDoesNotCloseABoxThatFdHasOpened) {
  std::filesystem::create_directories(LivePath().parent_path());
  {
    std::ofstream out(LivePath(), std::ios::trunc);
    out << "1\n";
  }
  ASSERT_TRUE(ApplySysctl(cfg_, opts_).has_value());
  EXPECT_EQ(ReadLiveSysctl(opts_.proc_dir, "net.ipv4.ip_forward"),
            "1");
}

TEST_F(SysctlTest, ASecondApplyChangesNothingAndSaysSo) {
  ASSERT_TRUE(ApplySysctl(cfg_, opts_).has_value());
  auto again = ApplySysctl(cfg_, opts_);
  ASSERT_TRUE(again.has_value());
  EXPECT_FALSE(again->changed);
  EXPECT_TRUE(again->applied.empty());
}

TEST_F(SysctlTest, AHandEditIsRefusedRatherThanOverwritten) {
  ASSERT_TRUE(ApplySysctl(cfg_, opts_).has_value());
  auto unit = PlanSysctl(cfg_, opts_);
  {
    std::ofstream out(unit.path, std::ios::app);
    out << "net.ipv4.ip_forward = 0\n";
  }
  EXPECT_EQ(CheckSysctlDrift(PlanSysctl(cfg_, opts_)),
            DriftKind::kHandEdited);
  auto refused = ApplySysctl(cfg_, opts_);
  EXPECT_FALSE(refused.has_value());

  auto forced = opts_;
  forced.refuse_on_drift = false;
  EXPECT_TRUE(ApplySysctl(cfg_, forced).has_value());
  EXPECT_EQ(CheckSysctlDrift(PlanSysctl(cfg_, opts_)), DriftKind::kNone);
}

/// `apply_live` is kept as a seam even though nothing here is applied
/// live any more, and the report has to keep saying "applied nothing"
/// either way — a report that said "applied" for a knob it did not
/// write is the shape of defect this project keeps finding.
TEST_F(SysctlTest, ApplyLiveOffInstallsTheFileAndTouchesNoKnob) {
  auto opts = opts_;
  opts.apply_live = false;
  auto r = ApplySysctl(cfg_, opts);
  ASSERT_TRUE(r.has_value());
  EXPECT_TRUE(std::filesystem::exists(r->unit.path));
  EXPECT_TRUE(r->applied.empty());
  EXPECT_FALSE(std::filesystem::exists(LivePath()));
}

TEST_F(SysctlTest, AnUnreadableKnobReadsAsEmptyRatherThanAsZero) {
  // Distinguishable from a real "0": a status line that cannot tell
  // "forwarding is off" from "I could not look" is worse than none.
  EXPECT_EQ(ReadLiveSysctl(opts_.proc_dir, "net.ipv4.ip_forward"), "");
  ASSERT_TRUE(ApplySysctl(cfg_, opts_).has_value());
  std::filesystem::create_directories(LivePath().parent_path());
  {
    std::ofstream out(LivePath(), std::ios::trunc);
    out << "0\n";
  }
  EXPECT_EQ(ReadLiveSysctl(opts_.proc_dir, "net.ipv4.ip_forward"), "0");
}

}  // namespace
}  // namespace f::sysconfig
