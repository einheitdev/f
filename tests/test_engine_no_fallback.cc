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
  // A socket address no test binds; every case below must fail before
  // EngineInit reaches the ZMQ step.
  static constexpr const char* kSock = "ipc:///tmp/f-no-fallback.sock";
  fs::path scratch_;
};

TEST_F(NoFallbackTest, NoBundleDirIsRefused) {
  Engine e;
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test", "");
  ASSERT_FALSE(res);
  EXPECT_EQ(res.error().code, EngineError::kInvalidConfig);
}

TEST_F(NoFallbackTest, AbsentCurrentIsRefused) {
  // The exact shape of the deb-03 experiment: a configured bundle root
  // with no `current` in it. This used to load `/usr/lib/f/fw.bpf.o`.
  Engine e;
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
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-test",
                        scratch_.string());
  ASSERT_FALSE(res);
  const auto& m = res.error().message;
  EXPECT_NE(m.find((scratch_ / "current").string()),
            std::string::npos) << m;
  EXPECT_NE(m.find("fwl compile"), std::string::npos) << m;
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
                    Cmd::kGetConntrack, Cmd::kGetFwlCounters}) {
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
