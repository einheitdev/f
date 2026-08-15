/// @file test_engine_no_fallback.cc
/// @brief `fd` has one way to get a policy, and refuses without it.
///
/// This file exists because of what the removed alternative did when it
/// ran. Measured on deb-03 against master `dc0b0fc`, with the staged
/// bundle's `current` symlink moved aside:
///
///   [I] Loading BPF program...
///   [I] Loaded BPF object from /usr/lib/f/fw.bpf.o
///   [W] Pin maps failed: pin /sys/fs/bpf/f/rules_a failed: File exists
///   [I] XDP attached to fwan0 (ifindex=234)
///   [I] Engine running. 1 interfaces.
///
/// systemd reported the unit Started. `fctl status` reported
/// `xdp_attached: true` and the counter climbing. And three pings
/// across the wire went straight through, because `LoadProgram` seeded
/// that program's config map with `default_action = kAllow` "so we
/// don't lock ourselves out before rules are configured" — a firewall
/// whose fallback is ALLOW, indistinguishable from a working one in
/// every view an operator has.
///
/// The reachability that made it possible was not exotic. Nothing
/// installs `/usr/lib/f/fw.bpf.o`, but `deploy/README.md` told
/// operators the fallback existed and named the path, and deb-03 had
/// one there since June. So the rule is now structural rather than
/// circumstantial: no bundle, no daemon.

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

#include "f/engine.h"
#include "f/protocol.h"

namespace f {
namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

class NoFallbackTest : public ::testing::Test {
 protected:
  void SetUp() override {
    scratch_ = fs::temp_directory_path()
        / std::format("f-no-fallback-{}-{}", ::getpid(),
                      ::testing::UnitTest::GetInstance()
                          ->current_test_info()->name());
    fs::create_directories(scratch_);
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(scratch_, ec);
  }
  void WriteManifest(const json& manifest) {
    auto dir = scratch_ / "current";
    fs::create_directories(dir);
    std::ofstream(dir / "manifest.json") << manifest.dump();
  }
  /// An Engine whose forwarding knob is a file in the scratch tree.
  ///
  /// Not a convenience. `EngineInit` now WRITES
  /// `<proc_dir>/net/ipv4/ip_forward`, and a test that left the
  /// default pointing at /proc/sys would turn forwarding off on
  /// whatever machine ran it — silently, if it happened to run as
  /// root, and this suite is run as root on the rig.
  auto MakeEngine(Engine* e) -> void {
    e->route.proc_dir = (scratch_ / "proc-sys").string();
    fs::create_directories(scratch_ / "proc-sys" / "net" / "ipv4");
    std::ofstream(scratch_ / "proc-sys" / "net" / "ipv4" /
                  "ip_forward") << "1\n";
  }
  auto LiveForwarding() const -> std::string {
    std::ifstream in(scratch_ / "proc-sys" / "net" / "ipv4" /
                     "ip_forward");
    std::string v;
    std::getline(in, v);
    return v;
  }

  // A socket address no test binds; every case below must fail before
  // EngineInit reaches the ZMQ step.
  static constexpr const char* kSock = "ipc:///tmp/f-no-fallback.sock";
  fs::path scratch_;
};

TEST_F(NoFallbackTest, NoBundleDirIsRefused) {
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test", "");
  ASSERT_FALSE(res);
  EXPECT_EQ(res.error().code, EngineError::kInvalidConfig);
}

TEST_F(NoFallbackTest, AbsentCurrentIsRefused) {
  // The exact shape of the deb-03 experiment: a configured bundle root
  // with no `current` in it. This used to load `/usr/lib/f/fw.bpf.o`.
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test",
                        scratch_.string());
  ASSERT_FALSE(res);
  EXPECT_EQ(res.error().code, EngineError::kBpfLoadFailed);
  EXPECT_NE(res.error().message.find("not a compiled bundle"),
            std::string::npos)
      << res.error().message;
}

TEST_F(NoFallbackTest, AV01ManifestIsRefused) {
  // A box staged by a pre-v0.4 deployment. Its manifest is well-formed
  // and names a `main.bpf.o`; it is still not something this daemon can
  // enforce, and the answer is a refusal rather than a second loader.
  WriteManifest(json{{"version", "20260414T000000Z"},
                     {"has_program", true},
                     {"program", {{"path", "main.bpf.o"}}}});
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test",
                        scratch_.string());
  ASSERT_FALSE(res);
  EXPECT_EQ(res.error().code, EngineError::kBpfLoadFailed);
}

TEST_F(NoFallbackTest, AManifestWithNoProgramsIsRefused) {
  WriteManifest(json{{"version", "0.4"},
                     {"zones", json::array()},
                     {"programs", json::array()}});
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test",
                        scratch_.string());
  ASSERT_FALSE(res);
  EXPECT_EQ(res.error().code, EngineError::kBpfLoadFailed);
}

TEST_F(NoFallbackTest, TheRefusalNamesTheDirectoryAndTheCompiler) {
  // An operator reading this line has to be able to act on it without
  // reading the source. It must say which directory was looked at and
  // what would put a bundle there.
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test",
                        scratch_.string());
  ASSERT_FALSE(res);
  const auto& m = res.error().message;
  EXPECT_NE(m.find((scratch_ / "current").string()),
            std::string::npos) << m;
  EXPECT_NE(m.find("fwl compile"), std::string::npos) << m;
}

// --- and the box does not forward what it is not filtering ----------
//
// The other half of the same finding, measured on a booted image on
// 2026-08-15: `fd` refused a missing bundle exactly as the cases above
// require, attached nothing, went to auto-restart, left
// /sys/fs/bpf/f/ empty — and the box went on ROUTING, because
// `f-sysconf apply` had written net.ipv4.ip_forward=1 once at
// provisioning time and systemd-sysctl reapplied it every boot. An
// unsolicited inbound TCP connection the healthy box refused with zero
// frames on the inside wire completed with four, and outbound flows
// left un-masqueraded carrying inside addresses, because the NAT lived
// in the XDP program that was not there.
//
// A refusal that leaves the box forwarding is not a refusal.

TEST_F(NoFallbackTest, ARefusedBundleLeavesTheBoxNotForwarding) {
  Engine e;
  MakeEngine(&e);
  ASSERT_EQ(LiveForwarding(), "1");
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test",
                        scratch_.string());
  ASSERT_FALSE(res);
  EXPECT_EQ(LiveForwarding(), "0");
  EXPECT_FALSE(e.route.desired_forwarding);
}

TEST_F(NoFallbackTest, AnAbsentBundleDirectoryClosesTheBoxToo) {
  // The earliest refusal there is — no bundle root configured at all.
  // It returns before any bundle is looked at, which is exactly the
  // path on which a "lower it once we know what we loaded" version of
  // this would have been skipped.
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test", "");
  ASSERT_FALSE(res);
  EXPECT_EQ(LiveForwarding(), "0");
}

TEST_F(NoFallbackTest, TheRefusedBoxSaysWhyItIsNotForwarding) {
  // Loudness is half the operator decision: a box that has stopped
  // forwarding must be a VISIBLE fault. The reason travels in the
  // state the CLI renders, not only in a log line that has scrolled.
  Engine e;
  MakeEngine(&e);
  (void)EngineInit(e, kSock, "/sys/fs/bpf/f-test", scratch_.string());
  auto j = GetFullState(e);
  ASSERT_TRUE(j["route"].contains("forwarding_reason")) << j.dump();
  EXPECT_FALSE(j["route"]["forwarding_desired"].get<bool>());
  EXPECT_FALSE(j["route"]["ip_forward"].get<bool>());
  EXPECT_FALSE(
      j["route"]["forwarding_reason"].get<std::string>().empty());
}

TEST_F(NoFallbackTest, StoppingClosesTheBoxBeforeDetachingXdp) {
  // `systemctl stop fd` is the first step in the handbook's own
  // recovery procedure, and it detaches XDP from every port. Between
  // that and the kernel giving up routing there must be no window in
  // which this box is a plain unfiltered router.
  Engine e;
  MakeEngine(&e);
  e.route.SetForwarding(true, "test: pretend the datapath is armed");
  ASSERT_EQ(LiveForwarding(), "1");
  EngineStop(e);
  EXPECT_EQ(LiveForwarding(), "0");
  EXPECT_FALSE(e.route.desired_forwarding);
}

// --- the control surface the removal leaves behind ------------------

TEST(RetiredOpcodes, AreAnsweredUnknownRatherThanSilently) {
  // An older `einheit-f` on an upgraded box sends 7 for
  // `show firewall rules`. It must get a refusal it can render, not a
  // hang and not another command's reply.
  Engine e;
  for (uint8_t retired : {1, 2, 6, 7, 8}) {
    std::string req(1, static_cast<char>(retired));
    auto reply = HandleControlRequest(e, req);
    auto j = json::parse(reply);
    ASSERT_TRUE(j.contains("error"))
        << "opcode " << static_cast<int>(retired) << " -> " << reply;
    EXPECT_EQ(j["error"].get<std::string>(), "unknown command");
  }
}

TEST(RetiredOpcodes, TheLiveOnesStillAnswer) {
  // The guard against over-deletion: the same dispatch table still
  // serves everything that was not part of the v0.1 surface.
  Engine e;
  for (auto live : {Cmd::kGetStatus, Cmd::kGetZones, Cmd::kGetNat,
                    Cmd::kGetConntrack, Cmd::kGetFwlCounters,
                    Cmd::kGetFwlRules}) {
    std::string req(1, static_cast<char>(live));
    auto reply = HandleControlRequest(e, req);
    auto j = json::parse(reply);
    if (j.is_object()) {
      EXPECT_FALSE(j.value("error", std::string())
                   == "unknown command")
          << "opcode " << static_cast<int>(live) << " went missing";
    }
  }
}

TEST(NamedCounters, AnswerTheAgreedShapeWithNoBundleLoaded) {
  // The gap the v0.1 removal left stated: `count` wrote into
  // fwl_counters_<zone> and nothing read it. Opcode 12 does — and on a
  // daemon holding no bundle it answers the agreed shape with no
  // zones, rather than an error the CLI would render as "fd is
  // broken" or a bare array the CLI cannot tell from a failure.
  Engine e;
  std::string req(1, static_cast<char>(Cmd::kGetFwlCounters));
  auto j = json::parse(HandleControlRequest(e, req));
  ASSERT_TRUE(j.is_object()) << j.dump();
  ASSERT_TRUE(j.contains("zones")) << j.dump();
  EXPECT_TRUE(j["zones"].is_array());
  EXPECT_TRUE(j["zones"].empty());
  EXPECT_FALSE(j.contains("error"));
}

TEST(LoadedRules, AnswerTheAgreedShapeWithNoBundleLoaded) {
  // Opcode 13 on a daemon holding no bundle: the agreed shape with no
  // zones and a source that says it is unknown. Not an error the CLI
  // would render as "fd is broken", and not a bare array it could not
  // tell from a failure.
  Engine e;
  std::string req(1, static_cast<char>(Cmd::kGetFwlRules));
  auto j = json::parse(HandleControlRequest(e, req));
  ASSERT_TRUE(j.is_object()) << j.dump();
  ASSERT_TRUE(j.contains("zones")) << j.dump();
  EXPECT_TRUE(j["zones"].is_array());
  EXPECT_TRUE(j["zones"].empty());
  ASSERT_TRUE(j.contains("source")) << j.dump();
  EXPECT_FALSE(j["source"].value("known", true));
  EXPECT_FALSE(j.contains("error"));
}

TEST(LoadedRules, ComeFromTheHandlesRatherThanTheBundleDirectory) {
  // The whole discipline in one assertion. The rules the daemon serves
  // are the ones captured on the ZoneProgramHandle at load; no path is
  // consulted here, so a bundle directory recompiled behind the
  // daemon's back cannot change this answer.
  Engine e;
  ZoneProgramHandle zh;
  zh.zone = "edge";
  zh.rules.zone = "edge";
  zh.rules.availability = RuleAvailability::kListed;
  LoadedRule r;
  r.action = "drop";
  r.match = "pkt.dst_port == 22";
  r.guarded = true;
  r.terminal = true;
  zh.rules.rules.push_back(r);
  e.zone_bundle.programs.push_back(zh);
  e.zone_bundle.policy_source.known = true;
  e.zone_bundle.policy_source.name = "office.fw";
  e.zone_bundle.policy_source.sha256 = std::string(64, 'a');

  std::string req(1, static_cast<char>(Cmd::kGetFwlRules));
  auto j = json::parse(HandleControlRequest(e, req));
  ASSERT_EQ(j["zones"].size(), 1u) << j.dump();
  EXPECT_EQ(j["zones"][0]["zone"], "edge");
  EXPECT_EQ(j["zones"][0]["availability"], "listed");
  ASSERT_EQ(j["zones"][0]["rules"].size(), 1u);
  EXPECT_EQ(j["zones"][0]["rules"][0]["match"], "pkt.dst_port == 22");
  EXPECT_TRUE(j["source"]["known"].get<bool>());
  EXPECT_EQ(j["source"]["name"], "office.fw");
}

TEST(FullState, CarriesNoRulesOrSlowPathSection) {
  // Both sections were structurally empty on every bundle box, and both
  // were rendered by `show status` as `active_table A` / `rule_count 0`
  // / `events 0`. A section nothing can fill is a claim, not a smaller
  // truth; re-adding either needs a datapath behind it.
  Engine e;
  auto j = GetFullState(e);
  EXPECT_FALSE(j.contains("rules"));
  EXPECT_FALSE(j.contains("slow_path"));
  // What did survive, because it is read from the kernel and the
  // bundle.
  EXPECT_TRUE(j.contains("interfaces"));
  EXPECT_TRUE(j.contains("conntrack"));
  EXPECT_TRUE(j.contains("nat"));
  EXPECT_TRUE(j.contains("route"));
  EXPECT_TRUE(j.contains("egress"));
}

}  // namespace
}  // namespace f
