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
/// The half that these tests are really about is `applied`. A drop-in
/// on disk that nobody has read is a box that forwards after the next
/// reboot and not now — which is the version of the fault that survives
/// a commissioning test, because the person who wrote the file also
/// rebooted at some point and never saw the gap.

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

TEST_F(SysctlTest, TheModelSaysTheBoxForwards) {
  auto values = PlanSysctlValues(cfg_);
  ASSERT_EQ(values.size(), 1U);
  EXPECT_EQ(values[0].first, "net.ipv4.ip_forward");
  EXPECT_EQ(values[0].second, "1");
}

/// Deriving it from the zone count was considered and rejected: it
/// creates a second way for the box to be silently non-routing. A
/// config with one zone and no services still says forward.
TEST_F(SysctlTest, ForwardingIsNotConditionalOnTheZoneCount) {
  auto bare = ParseSystemConfigString(
      "zones:\n  wan:\n\ninterfaces:\n  wan0:\n"
      "    mac: \"52:54:00:aa:bb:01\"\n    address: dhcp\n"
      "    zone: wan\n");
  ASSERT_TRUE(bare.has_value());
  auto values = PlanSysctlValues(*bare);
  ASSERT_EQ(values.size(), 1U);
  EXPECT_EQ(values[0].second, "1");
}

TEST_F(SysctlTest, TheDropInIsADerivedArtifactLikeEveryOther) {
  auto unit = PlanSysctl(cfg_, opts_);
  EXPECT_EQ(unit.path, (root_ / "sysctl.d" / "10-f-forwarding.conf"));
  EXPECT_NE(unit.content.find("net.ipv4.ip_forward = 1"),
            std::string::npos);
  // Nothing on disk yet, so the drift kind is kAbsent — not kNone,
  // which would say "identical to the model".
  EXPECT_EQ(CheckSysctlDrift(unit), DriftKind::kAbsent);
}

/// The whole point. Installed AND live, in one call, because a box
/// that has one without the other looks correct in exactly one of the
/// two states somebody will test it in.
TEST_F(SysctlTest, ApplyInstallsTheFileAndWritesTheLiveValue) {
  auto r = ApplySysctl(cfg_, opts_);
  ASSERT_TRUE(r.has_value()) << (r ? "" : r.error());
  EXPECT_TRUE(r->changed);
  EXPECT_TRUE(std::filesystem::exists(r->unit.path));
  ASSERT_EQ(r->applied.size(), 1U);
  EXPECT_EQ(r->applied[0], "net.ipv4.ip_forward");
  EXPECT_EQ(Read(LivePath()), "1\n");
  EXPECT_EQ(ReadLiveSysctl(opts_.proc_dir, "net.ipv4.ip_forward"), "1");
}

TEST_F(SysctlTest, ASecondApplyChangesNothingAndSaysSo) {
  ASSERT_TRUE(ApplySysctl(cfg_, opts_).has_value());
  auto again = ApplySysctl(cfg_, opts_);
  ASSERT_TRUE(again.has_value());
  EXPECT_FALSE(again->changed);
  // ...but the live value is still written, because the file being
  // unchanged says nothing about what the running kernel holds. A
  // reboot into a kernel that ignored the drop-in, or an operator who
  // set it to 0 by hand, both land here.
  EXPECT_EQ(again->applied.size(), 1U);
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

/// The live write is separable so a caller that only wants the file
/// (a packaging step, an image build) can say so — and it has to be
/// visible in the report, or "applied nothing" reads as "applied".
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
  {
    std::ofstream out(LivePath(), std::ios::trunc);
    out << "0\n";
  }
  EXPECT_EQ(ReadLiveSysctl(opts_.proc_dir, "net.ipv4.ip_forward"), "0");
}

}  // namespace
}  // namespace f::sysconfig
