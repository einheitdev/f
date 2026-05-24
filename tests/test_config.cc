/// @file test_config.cc
/// @brief Tests for fd.yaml parser.

#include <gtest/gtest.h>

#include <chrono>

#include "f/config.h"

namespace f {
namespace {

TEST(ConfigTest, EmptyDocumentGivesDefaults) {
  auto r = ParseConfigString("");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->socket_addr, "ipc:///tmp/fd-control.sock");
  EXPECT_EQ(r->pin_path, "/sys/fs/bpf/f");
  EXPECT_EQ(r->log_level, "info");
  EXPECT_FALSE(r->watch_enabled);
  EXPECT_EQ(r->watch_interval, std::chrono::seconds(5));
  EXPECT_TRUE(r->interfaces.empty());
}

TEST(ConfigTest, TopLevelScalars) {
  auto r = ParseConfigString(R"(
socket: tcp://0.0.0.0:9000
pin_path: /sys/fs/bpf/myfw
log_level: debug
)");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->socket_addr, "tcp://0.0.0.0:9000");
  EXPECT_EQ(r->pin_path, "/sys/fs/bpf/myfw");
  EXPECT_EQ(r->log_level, "debug");
}

TEST(ConfigTest, InterfacesArray) {
  auto r = ParseConfigString(R"(
interfaces:
  - eth0
  - wlan0
  - lo
)");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->interfaces.size(), 3u);
  EXPECT_EQ(r->interfaces[0], "eth0");
  EXPECT_EQ(r->interfaces[2], "lo");
}

TEST(ConfigTest, WatchSection) {
  auto r = ParseConfigString(R"(
watch:
  enabled: true
  interval: 10s
  source: /etc/f/rules.fw
  compiled_dir: /usr/share/f/compiled
  fwl: /usr/local/bin/fwl
)");
  ASSERT_TRUE(r);
  EXPECT_TRUE(r->watch_enabled);
  EXPECT_EQ(r->watch_interval, std::chrono::seconds(10));
  EXPECT_EQ(r->watch_source, "/etc/f/rules.fw");
  EXPECT_EQ(r->watch_compiled_dir,
            "/usr/share/f/compiled");
  EXPECT_EQ(r->watch_fwl, "/usr/local/bin/fwl");
}

TEST(ConfigTest, IntervalUnitless) {
  auto r = ParseConfigString(R"(
watch:
  enabled: true
  interval: 30
  source: /tmp/x.fw
)");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->watch_interval, std::chrono::seconds(30));
}

TEST(ConfigTest, IntervalMinutesAndHours) {
  auto r = ParseConfigString(R"(
watch:
  enabled: true
  interval: 2m
  source: /tmp/x.fw
)");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->watch_interval, std::chrono::seconds(120));

  r = ParseConfigString(R"(
watch:
  enabled: true
  interval: 1h
  source: /tmp/x.fw
)");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->watch_interval, std::chrono::seconds(3600));
}

TEST(ConfigTest, IntervalBadValueFails) {
  auto r = ParseConfigString(R"(
watch:
  enabled: true
  interval: never
  source: /tmp/x.fw
)");
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code, ConfigError::kInvalidValue);
}

TEST(ConfigTest, WatchEnabledRequiresSource) {
  auto r = ParseConfigString(R"(
watch:
  enabled: true
)");
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code, ConfigError::kInvalidValue);
}

TEST(ConfigTest, WatchDisabledIgnoresEmptySource) {
  auto r = ParseConfigString(R"(
watch:
  enabled: false
)");
  ASSERT_TRUE(r);
  EXPECT_FALSE(r->watch_enabled);
}

TEST(ConfigTest, MalformedYamlFails) {
  auto r = ParseConfigString("interfaces: [eth0,");
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code, ConfigError::kParseFailed);
}

TEST(ConfigTest, ParseFileMissingReportsNotFound) {
  auto r = ParseConfigFile("/nonexistent/never.yaml");
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code, ConfigError::kFileNotFound);
}

TEST(ConfigTest, FullExample) {
  auto r = ParseConfigString(R"(
interfaces:
  - eth0
socket: ipc:///run/f/fd.sock
pin_path: /sys/fs/bpf/f
log_level: info
watch:
  enabled: true
  interval: 5s
  source: /etc/f/rules.fw
  compiled_dir: /usr/share/f/compiled
)");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->interfaces.size(), 1u);
  EXPECT_EQ(r->socket_addr, "ipc:///run/f/fd.sock");
  EXPECT_TRUE(r->watch_enabled);
  EXPECT_EQ(r->watch_source, "/etc/f/rules.fw");
}

}  // namespace
}  // namespace f
