/// @file test_bpf_loader.cc
/// @brief Bundle manifest, pin reconciliation and attach-plan tests.
///
/// Four `ResolveBpfObjPath` tests were here, pinning the v0.1
/// cold-boot search list (`fw.bpf.o`, `build/fw.bpf.o`,
/// `../bpf/fw.bpf.o`, `/usr/lib/f/fw.bpf.o`) that `LoadProgram`
/// consulted when no bundle was staged. That list is gone; the shared
/// fixture below outlived it and the multi-zone tests still use it.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "f/bpf_loader.h"

namespace f {
namespace {

namespace fs = std::filesystem;

class BpfLoaderResolverTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Per-test scratch dir; cleared on TearDown.
    //
    // The prefix is `fwl-loader-`, NOT `fwl-bpf-loader-`. The Python
    // harness asserts that `bpf_runner.compile_c` leaves nothing
    // behind by globbing `fwl-bpf-*` in the temp directory, and this
    // fixture used to land inside that glob -- so a stale dir from an
    // old gtest run, swept by whatever tidies /tmp, made
    // test_bpf_runner fail intermittently in a suite that never ran
    // this binary. 620 of them had accumulated since August.
    base_ = fs::temp_directory_path()
        / std::format("fwl-loader-{}", ::getpid());
    auto suffix = ::testing::UnitTest::GetInstance()
                      ->current_test_info()
                      ->name();
    scratch_ = base_ / suffix;
    fs::create_directories(scratch_);
  }

  void TearDown() override {
    std::error_code ec;
    fs::remove_all(scratch_, ec);
    // The per-pid parent too, once its last test is done with it.
    // Removing only `scratch_` left one empty directory per test
    // process in /tmp forever.
    fs::remove(base_, ec);
  }

  // Drop a placeholder file at `path`, creating intermediate dirs.
  void Touch(const fs::path& path) {
    fs::create_directories(path.parent_path());
    std::ofstream(path) << "placeholder";
  }

  fs::path base_;
  fs::path scratch_;
};

// --- geoip.json bundle parsing (v0.4 hardware-validation gap) -------

class GeoipParseTest : public BpfLoaderResolverTest {
 protected:
  void WriteGeoip(const std::string& body) {
    std::ofstream(scratch_ / "geoip.json") << body;
  }
};

TEST_F(GeoipParseTest, AbsentFileYieldsEmptyTries) {
  auto tries = ParseGeoipFile(scratch_.string());
  ASSERT_TRUE(tries.has_value());
  EXPECT_TRUE(tries->empty());
}

TEST_F(GeoipParseTest, ParsesV4AndV6Prefixes) {
  WriteGeoip(R"({"tries": [
    {"map": "fwl_geoip_0", "family": "ipv4",
     "prefixes": ["10.99.77.0/24", "192.0.2.0/25"]},
    {"map": "fwl_geoip_1", "family": "ipv6",
     "prefixes": ["2001:db8::/32"]}
  ]})");
  auto tries = ParseGeoipFile(scratch_.string());
  ASSERT_TRUE(tries.has_value());
  ASSERT_EQ(tries->size(), 2u);

  const auto& v4 = tries->at("fwl_geoip_0");
  ASSERT_EQ(v4.size(), 2u);
  EXPECT_EQ(v4[0].prefixlen, 24u);
  EXPECT_FALSE(v4[0].v6);
  // 10.99.77.0 in network order.
  EXPECT_EQ(v4[0].addr[0], 10);
  EXPECT_EQ(v4[0].addr[1], 99);
  EXPECT_EQ(v4[0].addr[2], 77);
  EXPECT_EQ(v4[0].addr[3], 0);
  EXPECT_EQ(v4[1].prefixlen, 25u);

  const auto& v6 = tries->at("fwl_geoip_1");
  ASSERT_EQ(v6.size(), 1u);
  EXPECT_TRUE(v6[0].v6);
  EXPECT_EQ(v6[0].prefixlen, 32u);
  EXPECT_EQ(v6[0].addr[0], 0x20);
  EXPECT_EQ(v6[0].addr[1], 0x01);
  EXPECT_EQ(v6[0].addr[2], 0x0d);
  EXPECT_EQ(v6[0].addr[3], 0xb8);
}

// TABLES.md phase 1 emits a named table's prefixes into this same
// `tries` array, under the table's `fwl_tbl_<id>` map name. The claim
// that phase 1 needs no daemon change is exactly the claim that THIS
// function, unmodified, reads that payload -- so it is tested here
// rather than asserted in a commit message.
//
// The JSON below is `fwl compile --bundle` output copied verbatim.
// fwl/tests/unit/test_tables.py::TestTheDaemonReadsWhatTheCompiler
// Writes holds the other end, so a drift on either side goes red.
TEST_F(GeoipParseTest, ReadsATablePayloadTheCompilerEmitted) {
  WriteGeoip(R"({
  "tries": [
    {
      "map": "fwl_tbl_0",
      "family": "ipv4",
      "prefixes": [
        "10.99.77.0/24",
        "192.0.2.0/25"
      ]
    },
    {
      "map": "fwl_tbl_1",
      "family": "ipv6",
      "prefixes": [
        "2001:db8::/32"
      ]
    }
  ]
})");
  auto tries = ParseGeoipFile(scratch_.string());
  ASSERT_TRUE(tries.has_value());
  ASSERT_EQ(tries->size(), 2u);

  // PopulateGeoipTrie looks the map up by this name in each loaded
  // zone object and fills whatever LPM trie it finds. It neither
  // knows nor cares that these prefixes came from a `table`
  // declaration rather than from a country code.
  const auto& v4 = tries->at("fwl_tbl_0");
  ASSERT_EQ(v4.size(), 2u);
  EXPECT_FALSE(v4[0].v6);
  EXPECT_EQ(v4[0].prefixlen, 24u);
  EXPECT_EQ(v4[0].addr[0], 10);
  EXPECT_EQ(v4[0].addr[1], 99);
  EXPECT_EQ(v4[0].addr[2], 77);
  EXPECT_EQ(v4[0].addr[3], 0);
  EXPECT_EQ(v4[1].prefixlen, 25u);

  const auto& v6 = tries->at("fwl_tbl_1");
  ASSERT_EQ(v6.size(), 1u);
  EXPECT_TRUE(v6[0].v6);
  EXPECT_EQ(v6[0].prefixlen, 32u);
  EXPECT_EQ(v6[0].addr[0], 0x20);
  EXPECT_EQ(v6[0].addr[1], 0x01);
  EXPECT_EQ(v6[0].addr[2], 0x0d);
  EXPECT_EQ(v6[0].addr[3], 0xb8);
}

// A bundle whose policy mixes a geoip() call with a named table puts
// both tries in one array, and the loader must fill both: they are the
// same map type under different names, and dropping either would leave
// a rule matching against an empty trie.
TEST_F(GeoipParseTest, ReadsAGeoipTrieAndATableTrieTogether) {
  WriteGeoip(R"({"tries": [
    {"map": "fwl_geoip_eth0_0", "family": "ipv4",
     "prefixes": ["10.9.0.0/16"]},
    {"map": "fwl_tbl_0", "family": "ipv4",
     "prefixes": ["10.99.77.0/24"]}
  ]})");
  auto tries = ParseGeoipFile(scratch_.string());
  ASSERT_TRUE(tries.has_value());
  ASSERT_EQ(tries->size(), 2u);
  EXPECT_EQ(tries->at("fwl_geoip_eth0_0").size(), 1u);
  EXPECT_EQ(tries->at("fwl_tbl_0").size(), 1u);
}

// --- TABLES.md: the declaration ships, the data does not ------------

class TableSpecTest : public BpfLoaderResolverTest {
 protected:
  void WriteManifest(const std::string& body) {
    std::ofstream(scratch_ / "manifest.json") << body;
  }

  // A feed file inside the scratch dir, returned as an absolute path
  // so a TableSpec can name it the way a real one names an appliance
  // path.
  auto WriteFeed(const std::string& name, const std::string& body)
      -> std::string {
    auto path = scratch_ / name;
    std::ofstream(path) << body;
    return path.string();
  }

  auto Spec(const std::string& source, uint32_t max = 1000,
            bool v6 = false) -> TableSpec {
    TableSpec spec;
    spec.name = "badhosts";
    spec.id = 0;
    spec.map_name = "fwl_tbl_0";
    spec.v6 = v6;
    spec.max_entries = max;
    spec.source = source;
    return spec;
  }
};

TEST_F(TableSpecTest, AbsentManifestYieldsNoTables) {
  auto specs = ParseTableSpecs(scratch_.string());
  ASSERT_TRUE(specs.has_value());
  EXPECT_TRUE(specs->empty());
}

TEST_F(TableSpecTest, AbsentTablesBlockYieldsNoTables) {
  // A bundle compiled before tables existed, or a policy with none.
  WriteManifest(R"({"version": "0.4", "zones": []})");
  auto specs = ParseTableSpecs(scratch_.string());
  ASSERT_TRUE(specs.has_value());
  EXPECT_TRUE(specs->empty());
}

TEST_F(TableSpecTest, ParsesTheDeclarationTheCompilerShips) {
  // Copied from `fwl compile --bundle` output. The bundle carries the
  // declaration and NOT a single prefix: the file lives on the
  // appliance and this daemon is what reads it.
  WriteManifest(R"({
  "tables": {
    "corporate_blocklist": {
      "id": 0,
      "map": "fwl_tbl_0",
      "kind": "cidr4",
      "max": 100000,
      "source": "/var/lib/f/feeds/corp.txt",
      "referenced": true
    },
    "v6_blocklist": {
      "id": 1,
      "map": "fwl_tbl_1",
      "kind": "cidr6",
      "max": 100,
      "source": "/var/lib/f/feeds/corp6.txt",
      "referenced": true
    }
  }
})");
  auto specs = ParseTableSpecs(scratch_.string());
  ASSERT_TRUE(specs.has_value());
  ASSERT_EQ(specs->size(), 2u);
  const TableSpec* v4 = nullptr;
  const TableSpec* v6 = nullptr;
  for (const auto& s : *specs) {
    if (s.name == "corporate_blocklist") v4 = &s;
    if (s.name == "v6_blocklist") v6 = &s;
  }
  ASSERT_NE(v4, nullptr);
  ASSERT_NE(v6, nullptr);
  EXPECT_EQ(v4->map_name, "fwl_tbl_0");
  EXPECT_FALSE(v4->v6);
  EXPECT_EQ(v4->max_entries, 100000u);
  EXPECT_EQ(v4->source, "/var/lib/f/feeds/corp.txt");
  EXPECT_TRUE(v6->v6);
  EXPECT_EQ(v6->max_entries, 100u);
}

TEST_F(TableSpecTest, ATableNoRuleMatchesIsRecordedButNotFilled) {
  WriteManifest(R"({"tables": {"unused": {"id": 0, "referenced": false,
    "kind": "cidr4", "max": 10, "source": "/nope"}}})");
  auto specs = ParseTableSpecs(scratch_.string());
  ASSERT_TRUE(specs.has_value());
  ASSERT_EQ(specs->size(), 1u);
  EXPECT_FALSE((*specs)[0].referenced);
}

TEST_F(TableSpecTest, ATableWithoutCapacityIsRefused) {
  // Capacity is what makes "refuse rather than truncate" enforceable.
  // Guessing one reinstates the behaviour the rule exists to prevent.
  WriteManifest(R"({"tables": {"t": {"id": 0, "map": "fwl_tbl_0",
    "kind": "cidr4", "source": "/f"}}})");
  auto specs = ParseTableSpecs(scratch_.string());
  EXPECT_FALSE(specs.has_value());
}

TEST_F(TableSpecTest, ATableWithoutASourceIsRefused) {
  WriteManifest(R"({"tables": {"t": {"id": 0, "map": "fwl_tbl_0",
    "kind": "cidr4", "max": 10}}})");
  auto specs = ParseTableSpecs(scratch_.string());
  EXPECT_FALSE(specs.has_value());
}

// --- Reading a feed: empty is a failure, never a state --------------

class TableFeedTest : public TableSpecTest {};

TEST_F(TableFeedTest, ReadsPrefixesCommentsAndBlanks) {
  auto path = WriteFeed("feed.txt",
      "# a threat feed\n"
      "\n"
      "10.99.77.0/24\n"
      "  192.0.2.0/25   # trailing comment\n"
      "\n");
  auto entries = ReadTableFeed(Spec(path));
  ASSERT_TRUE(entries.has_value()) << entries.error().message;
  ASSERT_EQ(entries->size(), 2u);
}

TEST_F(TableFeedTest, ARepeatedPrefixCountsOnce) {
  // One entry in an LPM trie, so counting it twice would refuse a feed
  // the map would have held.
  auto path = WriteFeed("feed.txt",
      "10.0.0.0/8\n10.0.0.0/8\n192.168.0.0/16\n");
  auto entries = ReadTableFeed(Spec(path, 2));
  ASSERT_TRUE(entries.has_value()) << entries.error().message;
  EXPECT_EQ(entries->size(), 2u);
}

TEST_F(TableFeedTest, AMissingFileIsAFeedFailureNotALoadFailure) {
  // The distinction a bundle-health guard needs: the artifact is fine,
  // its data is not. Counting this as a failed load would spend a good
  // policy's attempts on an NFS blip.
  auto entries = ReadTableFeed(Spec("/definitely/not/here.txt"));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
  EXPECT_NE(entries.error().message.find("badhosts"), std::string::npos);
}

TEST_F(TableFeedTest, ADirectoryWhereAFileShouldBeIsAFeedFailure) {
  auto entries = ReadTableFeed(Spec(scratch_.string()));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
}

TEST_F(TableFeedTest, AnEmptyFeedIsRefusedRatherThanApplied) {
  // The safe reading of "the blocklist is now empty" is "the feeder is
  // broken", not "nothing is dangerous any more". A query that failed,
  // an API that returned 200 with no body, an expired credential --
  // all of them produce this file.
  auto path = WriteFeed("feed.txt", "# nothing but a comment\n\n");
  auto entries = ReadTableFeed(Spec(path));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
  EXPECT_NE(entries.error().message.find("no prefixes"),
            std::string::npos);
}

TEST_F(TableFeedTest, MorePrefixesThanCapacityIsRefusedNotTruncated) {
  auto path = WriteFeed("feed.txt",
      "10.0.0.0/8\n192.168.0.0/16\n172.16.0.0/12\n");
  auto entries = ReadTableFeed(Spec(path, 2));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
  // The message says how many did not fit rather than leaving the
  // operator to count.
  EXPECT_NE(entries.error().message.find("1 entries"),
            std::string::npos);
}

TEST_F(TableFeedTest, AV6PrefixInACidr4TableIsRefused) {
  auto path = WriteFeed("feed.txt", "10.0.0.0/8\n2001:db8::/32\n");
  auto entries = ReadTableFeed(Spec(path));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
  EXPECT_NE(entries.error().message.find(":2:"), std::string::npos);
}

TEST_F(TableFeedTest, AnAddressWithoutAPrefixLengthIsRefused) {
  auto path = WriteFeed("feed.txt", "10.0.0.0\n");
  auto entries = ReadTableFeed(Spec(path));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
}

TEST_F(TableFeedTest, APrefixLengthPastTheKeyWidthIsRefused) {
  auto path = WriteFeed("feed.txt", "10.0.0.0/33\n");
  auto entries = ReadTableFeed(Spec(path));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
}

TEST_F(TableFeedTest, AV6FeedReadsSixteenAddressBytes) {
  auto path = WriteFeed("feed6.txt", "2001:db8::/32\n");
  auto entries = ReadTableFeed(Spec(path, 100, /*v6=*/true));
  ASSERT_TRUE(entries.has_value()) << entries.error().message;
  ASSERT_EQ(entries->size(), 1u);
  EXPECT_TRUE((*entries)[0].v6);
  EXPECT_EQ((*entries)[0].prefixlen, 32u);
  EXPECT_EQ((*entries)[0].addr[0], 0x20);
  EXPECT_EQ((*entries)[0].addr[3], 0xb8);
}

TEST_F(TableFeedTest, AV4AddressInACidr6TableIsRefused) {
  auto path = WriteFeed("feed6.txt", "10.0.0.0/8\n");
  auto entries = ReadTableFeed(Spec(path, 100, /*v6=*/true));
  ASSERT_FALSE(entries.has_value());
  EXPECT_EQ(entries.error().code, BpfError::kFeedUnavailable);
}

// --- The ordering that keeps a transient from costing a policy ------

class TableLoadOrderTest : public BpfLoaderResolverTest {
 protected:
  // A manifest that is otherwise loadable: one zone, one program, and
  // a table whose feed is not there.
  void WriteBundle(const std::string& source) {
    std::ofstream(scratch_ / "manifest.json") << std::format(R"({{
  "version": "0.4",
  "zones": [{{"name": "wan", "interfaces": ["nonexistent0"]}}],
  "programs": [{{"zone": "wan", "source": "wan.bpf.c",
                "object": "wan.bpf.o"}}],
  "persistent_maps": ["conntrack", "fwl_nat", "fwl_tbl_0"],
  "tables": {{
    "badhosts": {{"id": 0, "map": "fwl_tbl_0", "kind": "cidr4",
                 "max": 1000, "source": "{}", "referenced": true}}
  }}
}})", source);
  }
};

TEST_F(TableLoadOrderTest, AnUnreadableFeedFailsBeforeAnythingIsLoaded) {
  // The property a bundle-health guard depends on. fd.service carries
  // Restart=on-failure and a guard counts load attempts, so if an NFS
  // blip or a feeder that has not written yet reported the same thing
  // a broken artifact reports, a transient would spend a good
  // policy's remaining attempts and quarantine it.
  //
  // Two halves, both asserted here: the code is kFeedUnavailable and
  // not kLoadFailed, and the failure happens before the loader opens
  // an object at all -- note that wan.bpf.o does not exist in the
  // scratch dir, so reaching the object stage would give kLoadFailed
  // instead. Failing first is what makes the attempt cost nothing.
  WriteBundle("/definitely/not/here.txt");
  auto handles = LoadZoneBundle(scratch_.string(),
                                (scratch_ / "pins").string(), nullptr);
  ASSERT_FALSE(handles.has_value());
  EXPECT_EQ(handles.error().code, BpfError::kFeedUnavailable);
  EXPECT_NE(handles.error().message.find("badhosts"),
            std::string::npos);
}

TEST_F(TableLoadOrderTest, AnEmptyFeedFailsTheSameWay) {
  auto feed = scratch_ / "empty.txt";
  std::ofstream(feed) << "# the feeder ran and produced nothing\n";
  WriteBundle(feed.string());
  auto handles = LoadZoneBundle(scratch_.string(),
                                (scratch_ / "pins").string(), nullptr);
  ASSERT_FALSE(handles.has_value());
  EXPECT_EQ(handles.error().code, BpfError::kFeedUnavailable);
}

TEST_F(TableLoadOrderTest, ABrokenBundleStillReportsALoadFailure) {
  // The other side of the distinction, and the one that must NOT
  // become kFeedUnavailable: a readable feed and a missing object is
  // an artifact that will never work, and a guard should count it.
  auto feed = scratch_ / "feed.txt";
  std::ofstream(feed) << "10.0.0.0/8\n";
  WriteBundle(feed.string());
  auto handles = LoadZoneBundle(scratch_.string(),
                                (scratch_ / "pins").string(), nullptr);
  ASSERT_FALSE(handles.has_value());
  EXPECT_NE(handles.error().code, BpfError::kFeedUnavailable);
}

TEST_F(TableLoadOrderTest, ATableNoRuleMatchesNeedsNoFeed) {
  // A declared-but-unmatched table has no map in any object, so a
  // missing feed for it must not fail the load -- refusing there
  // would make an unused declaration able to take the box down.
  std::ofstream(scratch_ / "manifest.json") << R"({
  "version": "0.4",
  "zones": [{"name": "wan", "interfaces": ["nonexistent0"]}],
  "programs": [{"zone": "wan", "source": "wan.bpf.c",
                "object": "wan.bpf.o"}],
  "tables": {
    "unused": {"id": 0, "kind": "cidr4", "max": 10,
               "source": "/definitely/not/here.txt",
               "referenced": false}
  }
})";
  auto handles = LoadZoneBundle(scratch_.string(),
                                (scratch_ / "pins").string(), nullptr);
  ASSERT_FALSE(handles.has_value());
  // It still fails -- wan.bpf.o is not there -- but for the bundle's
  // own reason and not for the feed's.
  EXPECT_NE(handles.error().code, BpfError::kFeedUnavailable);
}

// --- The diff: a table must never pass through empty -----------------
//
// This is the property the whole write path is shaped around. A
// blocklist that is briefly empty is an open firewall, and with a
// feeder on a timer that window recurs all day rather than once at
// deploy. Clear-and-refill would be simpler and is refused for that
// reason alone, so the refusal needs a test that a clear-and-refill
// implementation fails.

class TableSyncTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // BPF_F_NO_PREALLOC is mandatory for an LPM trie and is what the
    // emitted map declares, so the test map is the same shape the
    // datapath's is.
    LIBBPF_OPTS(bpf_map_create_opts, opts,
                .map_flags = BPF_F_NO_PREALLOC);
    map_fd_ = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, "fwl_tbl_0",
                             /*key_size=*/8, /*value_size=*/1,
                             /*max_entries=*/1024, &opts);
    if (map_fd_ < 0) {
      GTEST_SKIP() << "bpf_map_create failed (needs CAP_BPF)";
    }
  }

  void TearDown() override {
    if (map_fd_ >= 0) ::close(map_fd_);
  }

  static auto V4(const char* cidr) -> GeoipTrieEntry {
    std::string text(cidr);
    auto slash = text.find('/');
    GeoipTrieEntry e;
    e.v6 = false;
    e.prefixlen = static_cast<uint32_t>(
        std::stoul(text.substr(slash + 1)));
    inet_pton(AF_INET, text.substr(0, slash).c_str(), e.addr);
    return e;
  }

  auto Contains(const char* cidr) -> bool {
    auto e = V4(cidr);
    uint8_t key[8] = {};
    std::memcpy(key, &e.prefixlen, sizeof(e.prefixlen));
    std::memcpy(key + 4, e.addr, 4);
    uint8_t value = 0;
    return bpf_map_lookup_elem(map_fd_, key, &value) == 0;
  }

  auto Count() -> uint32_t {
    uint8_t key[8] = {};
    uint8_t next[8] = {};
    uint32_t n = 0;
    bool have = false;
    while (bpf_map_get_next_key(map_fd_, have ? key : nullptr, next) == 0) {
      n++;
      std::memcpy(key, next, sizeof(key));
      have = true;
    }
    return n;
  }

  int map_fd_ = -1;
};

TEST_F(TableSyncTest, AFreshMapTakesEveryEntry) {
  std::vector<GeoipTrieEntry> want = {
      V4("10.0.0.0/8"), V4("192.168.0.0/16"), V4("203.0.113.0/24")};
  auto report = SyncTableTrie(map_fd_, false, want);
  ASSERT_TRUE(report.has_value()) << report.error().message;
  EXPECT_EQ(report->added, 3u);
  EXPECT_EQ(report->removed, 0u);
  EXPECT_EQ(report->unchanged, 0u);
  EXPECT_EQ(Count(), 3u);
}

TEST_F(TableSyncTest, ASecondSyncOfTheSameFeedTouchesNothing) {
  // The steady state a feeder on a timer spends almost all its time
  // in. If this reported three adds, every refresh would be rewriting
  // the whole table for no reason.
  std::vector<GeoipTrieEntry> want = {
      V4("10.0.0.0/8"), V4("192.168.0.0/16"), V4("203.0.113.0/24")};
  ASSERT_TRUE(SyncTableTrie(map_fd_, false, want).has_value());
  auto report = SyncTableTrie(map_fd_, false, want);
  ASSERT_TRUE(report.has_value()) << report.error().message;
  EXPECT_EQ(report->added, 0u);
  EXPECT_EQ(report->removed, 0u);
  EXPECT_EQ(report->unchanged, 3u);
  EXPECT_EQ(Count(), 3u);
}

TEST_F(TableSyncTest, AnEntryInBothFeedsIsNeverRemovedAndNeverReadded) {
  // The refusal of clear-and-refill, stated as an assertion. An
  // implementation that emptied the map first would report this entry
  // as ADDED rather than unchanged, and for the interval between the
  // clear and the refill the datapath would have forwarded traffic
  // this table exists to drop.
  std::vector<GeoipTrieEntry> before = {
      V4("10.0.0.0/8"), V4("192.168.0.0/16")};
  ASSERT_TRUE(SyncTableTrie(map_fd_, false, before).has_value());

  std::vector<GeoipTrieEntry> after = {
      V4("10.0.0.0/8"), V4("203.0.113.0/24")};
  auto report = SyncTableTrie(map_fd_, false, after);
  ASSERT_TRUE(report.has_value()) << report.error().message;
  EXPECT_EQ(report->unchanged, 1u) << "10.0.0.0/8 was in both feeds";
  EXPECT_EQ(report->added, 1u);
  EXPECT_EQ(report->removed, 1u);

  EXPECT_TRUE(Contains("10.0.0.0/8"));
  EXPECT_TRUE(Contains("203.0.113.0/24"));
  EXPECT_FALSE(Contains("192.168.0.0/16"));
  EXPECT_EQ(Count(), 2u);
}

TEST_F(TableSyncTest, ShrinkingAFeedRemovesOnlyWhatLeftIt) {
  std::vector<GeoipTrieEntry> before = {
      V4("10.0.0.0/8"), V4("192.168.0.0/16"), V4("172.16.0.0/12")};
  ASSERT_TRUE(SyncTableTrie(map_fd_, false, before).has_value());
  std::vector<GeoipTrieEntry> after = {V4("10.0.0.0/8")};
  auto report = SyncTableTrie(map_fd_, false, after);
  ASSERT_TRUE(report.has_value()) << report.error().message;
  EXPECT_EQ(report->removed, 2u);
  EXPECT_EQ(report->unchanged, 1u);
  EXPECT_EQ(report->added, 0u);
  EXPECT_TRUE(Contains("10.0.0.0/8"));
  EXPECT_EQ(Count(), 1u);
}

TEST_F(TableSyncTest, AnAdoptedMapIsReconciledToTheFileNotMerged) {
  // What makes MapLifetime.EXTERNAL safe without an id registry. A
  // pin carried across a reload holds the PREVIOUS contents; after
  // the sync it holds exactly the file's, so a map object reused by a
  // table that renumbered cannot carry the other table's entries into
  // it.
  std::vector<GeoipTrieEntry> stale = {
      V4("198.51.100.0/24"), V4("198.51.100.7/32")};
  ASSERT_TRUE(SyncTableTrie(map_fd_, false, stale).has_value());
  std::vector<GeoipTrieEntry> file = {V4("10.0.0.0/8")};
  ASSERT_TRUE(SyncTableTrie(map_fd_, false, file).has_value());
  EXPECT_FALSE(Contains("198.51.100.0/24"));
  EXPECT_FALSE(Contains("198.51.100.7/32"));
  EXPECT_TRUE(Contains("10.0.0.0/8"));
  EXPECT_EQ(Count(), 1u);
}

TEST_F(GeoipParseTest, MalformedJsonIsAnError) {
  WriteGeoip("{not json");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

TEST_F(GeoipParseTest, PrefixWithoutLengthIsAnError) {
  WriteGeoip(R"({"tries": [{"map": "m", "family": "ipv4",
                "prefixes": ["10.0.0.0"]}]})");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

TEST_F(GeoipParseTest, PrefixLengthOutOfRangeIsAnError) {
  WriteGeoip(R"({"tries": [{"map": "m", "family": "ipv4",
                "prefixes": ["10.0.0.0/33"]}]})");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

TEST_F(GeoipParseTest, UnparseableAddressIsAnError) {
  WriteGeoip(R"({"tries": [{"map": "m", "family": "ipv4",
                "prefixes": ["not.an.ip/8"]}]})");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

// --- masquerade address resolution ----------------------------------

TEST(FirstZoneIpv4Test, LoopbackResolves) {
  // 127.0.0.1 in network order — the one address every host has.
  uint32_t addr = FirstZoneIpv4({"lo"});
  EXPECT_EQ(addr, htonl(0x7F000001u));
}

TEST(FirstZoneIpv4Test, UnknownInterfaceYieldsZero) {
  EXPECT_EQ(FirstZoneIpv4({"no-such-if0"}), 0u);
}

TEST(FirstZoneIpv4Test, FallsThroughToLaterInterface) {
  EXPECT_EQ(FirstZoneIpv4({"no-such-if0", "lo"}),
            htonl(0x7F000001u));
}

// --- pinned-map conflict diagnostic ---------------------------------
//
// libbpf answers a pin-shape mismatch with -EINVAL and nothing else,
// so the daemon's job is to convert that into the one sentence an
// operator can act on: which map, which zones, which numbers.

TEST(DescribePinConflictTest, NamesTheMapZonesAndValues) {
  PinnedMapShape want;
  want.type = 6;
  want.key_size = 4;
  want.value_size = 8;
  want.max_entries = 3;
  PinnedMapShape have = want;
  have.max_entries = 1;

  std::string message = DescribePinConflict(
      "fwl_counters", "b", "zone 'a'", want, have);

  EXPECT_NE(message.find("fwl_counters"), std::string::npos);
  EXPECT_NE(message.find("zone 'b'"), std::string::npos);
  EXPECT_NE(message.find("zone 'a'"), std::string::npos);
  EXPECT_NE(message.find("max_entries 3 vs 1"), std::string::npos);
}

TEST(DescribePinConflictTest, ReportsEveryDifferingField) {
  PinnedMapShape want;
  want.type = 6;
  want.key_size = 4;
  want.value_size = 8;
  want.max_entries = 3;
  PinnedMapShape have;
  have.type = 2;
  have.key_size = 8;
  have.value_size = 16;
  have.max_entries = 3;

  std::string message = DescribePinConflict(
      "fwl_log_sample", "b", "zone 'a'", want, have);

  EXPECT_NE(message.find("type 6 vs 2"), std::string::npos);
  EXPECT_NE(message.find("key_size 4 vs 8"), std::string::npos);
  EXPECT_NE(message.find("value_size 8 vs 16"), std::string::npos);
  // Fields that agree must not be listed as differences.
  EXPECT_EQ(message.find("max_entries"), std::string::npos);
}

TEST(DescribePinConflictTest, IdenticalShapesExplainNothing) {
  // Not every failed load is a pin conflict. When the shapes agree
  // there is nothing to say, and the caller keeps libbpf's own error
  // rather than blaming an innocent map.
  PinnedMapShape shape;
  shape.type = 6;
  shape.key_size = 4;
  shape.value_size = 8;
  shape.max_entries = 3;
  EXPECT_TRUE(
      DescribePinConflict("conntrack", "b", "zone 'a'", shape, shape)
          .empty());
}

TEST(DescribePinConflictTest, SaysWhatToDoAboutIt) {
  // The operator reading this at 3am needs the fix, not just the
  // fault: a name that carries the zone, or a shape that does not
  // come from a per-zone count.
  PinnedMapShape want;
  want.max_entries = 3;
  PinnedMapShape have;
  have.max_entries = 1;
  std::string message = DescribePinConflict(
      "fwl_counters", "b", "zone 'a'", want, have);
  EXPECT_NE(message.find("per-zone"), std::string::npos);
  EXPECT_NE(message.find("ONE kernel map"), std::string::npos);
}

// --- Pin reconciliation ---------------------------------------------
//
// What a load may inherit from bpffs. The pins are left by a PREVIOUS
// compilation — on reload by the policy still attached, on cold boot by
// a process that is gone — and the two questions are separate: do the
// contents still mean anything (MapLifetime, carried in the manifest as
// `persistent_maps`), and does the definition still match (the check
// libbpf makes, made early enough to say something useful).
//
// DecidePinFate is the whole decision as a pure function so it can be
// tested without bpffs or root; ReconcilePinnedMaps is the loop that
// applies it, covered on hardware by l8_09/l8_10.

namespace {

/// A shape distinct enough that any field mismatch is visible.
auto SomeShape() -> PinnedMapShape {
  PinnedMapShape s;
  s.type = 1;
  s.key_size = 16;
  s.value_size = 24;
  s.max_entries = 65536;
  s.map_flags = 0;
  return s;
}

const std::vector<std::string> kPersistent = {"conntrack", "fwl_nat"};

}  // namespace

TEST(DecidePinFateTest, PolicyScopedPinsAlwaysGo) {
  // Numbered or sized by the compilation that pinned them. Their shape
  // agreeing with the new bundle's proves nothing — slot 0 of the next
  // policy is a different rule — so a matching declaration must not
  // rescue them on either path.
  auto shape = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    for (const char* name : {"fwl_counters_a", "fwl_log_sample_a",
                             "fwl_rl_a_0", "fwl_rl_g0", "fwl_geoip_a_0",
                             "fwl_devmap_wan", "fwl_log_events",
                             "fwl_nat_cfg_a"}) {
      EXPECT_EQ(DecidePinFate(name, kPersistent, &shape, shape, policy),
                PinVerdict::kDiscard)
          << name;
    }
  }
}

TEST(DecidePinFateTest, FlowKeyedPinsAreAdoptedWhenTheyStillFit) {
  // conntrack and fwl_nat are keyed by the flow 5-tuple, which means
  // the same thing under any policy. This is the case that keeps
  // established connections alive across a reload AND across a
  // process restart.
  auto shape = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(
        DecidePinFate("conntrack", kPersistent, &shape, shape, policy),
        PinVerdict::kAdopt);
    EXPECT_EQ(
        DecidePinFate("fwl_nat", kPersistent, &shape, shape, policy),
        PinVerdict::kAdopt);
  }
}

TEST(DecidePinFateTest, AdoptionStillRequiresTheDefinitionToMatch) {
  // The back door: a map allowed to persist is still only reusable if
  // the incoming bundle declares it exactly as it is pinned. Skipping
  // this check would reintroduce the -EINVAL load failure through the
  // one map that is permitted to survive.
  auto have = SomeShape();
  auto want = have;
  want.max_entries = 4096;
  EXPECT_NE(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kColdBoot),
            PinVerdict::kAdopt);
  EXPECT_NE(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kReload),
            PinVerdict::kAdopt);
}

TEST(DecidePinFateTest, ColdBootDiscardsWhatItCannotReuse) {
  // No running policy to fall back on: deferring to the loader means
  // fd exits, systemd restarts it, and it fails the same way forever
  // with nothing attached. Discarding costs a conntrack table; not
  // starting costs the whole firewall.
  auto have = SomeShape();
  auto want = have;
  want.value_size = 32;
  EXPECT_EQ(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kColdBoot),
            PinVerdict::kDiscard);
}

TEST(DecidePinFateTest, ReloadDefersToTheLoaderInstead) {
  // On reload the old policy is attached and filtering. Destroying
  // live state to force the new bundle in would be the wrong trade:
  // let the load fail, keep what is running, and let
  // ExplainPinConflict name the map and the numbers.
  auto have = SomeShape();
  auto want = have;
  want.value_size = 32;
  EXPECT_EQ(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kReload),
            PinVerdict::kDefer);
}

TEST(DecidePinFateTest, UndeclaredPersistentPinIsDroppedNotHoarded) {
  // conntrack pinned, but no zone of the incoming bundle uses
  // conntrack. Nothing reads it and nothing ages it out — GC only runs
  // while a loaded bundle carries the map — so keeping it means a
  // later policy that re-adds conntrack would adopt entries of
  // arbitrary age.
  auto have = SomeShape();
  EXPECT_EQ(DecidePinFate("conntrack", kPersistent, nullptr, have,
                          PinPolicy::kColdBoot),
            PinVerdict::kDiscard);
}

// --- The reload itself, on real bpffs with real entries ------------
//
// DecidePinFate above is the decision; this is the decision applied.
// It runs the loop `fd` runs before every load, against a real pinned
// LPM trie holding real prefixes, and asks the question the acceptance
// criterion asks: after a policy edit that did not touch the table,
// are the entries still there?

class TablePinReloadTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // A per-test subdirectory of bpffs. Pinning needs a real bpffs;
    // a tmpfs path makes bpf_obj_pin return -EINVAL.
    root_ = std::filesystem::path("/sys/fs/bpf") /
            std::format("fwl-tbl-{}", ::getpid());
    std::error_code ec;
    std::filesystem::create_directories(root_, ec);
    if (ec) {
      GTEST_SKIP() << "cannot create " << root_.string()
                   << " (needs root and a mounted bpffs)";
    }
    LIBBPF_OPTS(bpf_map_create_opts, opts,
                .map_flags = BPF_F_NO_PREALLOC);
    trie_fd_ = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, "fwl_tbl_0", 8, 1,
                              1000, &opts);
    counters_fd_ = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY,
                                  "fwl_counters_wan", 4, 8, 4, nullptr);
    if (trie_fd_ < 0 || counters_fd_ < 0) {
      GTEST_SKIP() << "bpf_map_create failed (needs CAP_BPF)";
    }
    if (bpf_obj_pin(trie_fd_, (root_ / "fwl_tbl_0").c_str()) != 0 ||
        bpf_obj_pin(counters_fd_,
                    (root_ / "fwl_counters_wan").c_str()) != 0) {
      GTEST_SKIP() << "bpf_obj_pin failed";
    }
  }

  void TearDown() override {
    if (trie_fd_ >= 0) ::close(trie_fd_);
    if (counters_fd_ >= 0) ::close(counters_fd_);
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }

  // A bundle whose zone object declares the trie and the counter map
  // with the shapes created above. `persistent` is the manifest list
  // the compiler wrote.
  void WriteBundle(const std::string& persistent) {
    std::ofstream(scratch_dir() / "manifest.json") << std::format(R"({{
  "version": "0.4",
  "zones": [{{"name": "wan", "interfaces": ["eth0"]}}],
  "programs": [{{"zone": "wan", "source": "wan.bpf.c",
                "object": "wan.bpf.o"}}],
  "persistent_maps": [{}]
}})", persistent);
  }

  /// Build `wan.bpf.o`, because BundlePinnedDeclarations learns a
  /// bundle's declared shapes by opening the OBJECT with libbpf. A
  /// hand-written .bpf.c would not be read, and a hand-written shape
  /// struct would be this test agreeing with itself instead of with
  /// what the emitter produces.
  auto BuildObject() -> bool {
    auto src = scratch_dir() / "wan.bpf.c";
    std::ofstream(src) << R"(
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct fwl_tbl_0_key {
  __u32 prefixlen;
  __u32 ip;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct fwl_tbl_0_key);
  __type(value, __u8);
  __uint(max_entries, 1000);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} fwl_tbl_0 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 4);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} fwl_counters_wan SEC(".maps");

char _license[] SEC("license") = "GPL";
)";
    auto cmd = std::format(
        "clang -O2 -g -target bpf "
        "-I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu "
        "-c {} -o {} 2>/dev/null",
        src.string(), (scratch_dir() / "wan.bpf.o").string());
    return std::system(cmd.c_str()) == 0;
  }

  auto scratch_dir() -> std::filesystem::path {
    if (scratch_.empty()) {
      scratch_ = std::filesystem::temp_directory_path() /
                 std::format("fwl-tblbundle-{}", ::getpid());
      std::filesystem::create_directories(scratch_);
    }
    return scratch_;
  }

  void Insert(const char* cidr) {
    std::string text(cidr);
    auto slash = text.find('/');
    uint8_t key[8] = {};
    uint32_t len = static_cast<uint32_t>(
        std::stoul(text.substr(slash + 1)));
    std::memcpy(key, &len, sizeof(len));
    inet_pton(AF_INET, text.substr(0, slash).c_str(), key + 4);
    uint8_t one = 1;
    ASSERT_EQ(bpf_map_update_elem(trie_fd_, key, &one, BPF_ANY), 0);
  }

  auto CountVia(const std::filesystem::path& pin) -> int {
    int fd = bpf_obj_get(pin.c_str());
    if (fd < 0) return -1;
    uint8_t key[8] = {};
    uint8_t next[8] = {};
    int n = 0;
    bool have = false;
    while (bpf_map_get_next_key(fd, have ? key : nullptr, next) == 0) {
      n++;
      std::memcpy(key, next, sizeof(key));
      have = true;
    }
    ::close(fd);
    return n;
  }

  std::filesystem::path root_;
  std::filesystem::path scratch_;
  int trie_fd_ = -1;
  int counters_fd_ = -1;
};

TEST_F(TablePinReloadTest, APolicyEditLeavesTheTableIntact) {
  if (!BuildObject()) GTEST_SKIP() << "clang unavailable";
  // Write entries, "edit the policy", reload, read them back. The
  // counter map is the control: it is MapLifetime.POLICY, its pin is
  // NOT in persistent_maps, and it must be swept by the same pass
  // that keeps the table -- otherwise the test would pass on a
  // reconcile that simply kept everything.
  Insert("10.0.0.0/8");
  Insert("192.168.0.0/16");
  Insert("203.0.113.0/24");
  ASSERT_EQ(CountVia(root_ / "fwl_tbl_0"), 3);

  WriteBundle(R"("conntrack", "fwl_nat", "fwl_tbl_0")");
  auto report = ReconcilePinnedMaps(scratch_dir().string(),
                                    root_.string(), PinPolicy::kReload,
                                    /*conntrack_timeout_s=*/0);

  EXPECT_NE(std::find(report.adopted.begin(), report.adopted.end(),
                      "fwl_tbl_0"),
            report.adopted.end())
      << "the table was not adopted across the reload";
  EXPECT_NE(std::find(report.discarded.begin(), report.discarded.end(),
                      "fwl_counters_wan"),
            report.discarded.end())
      << "the control map survived, so this proves nothing";

  // The pin is still there and still holds every prefix.
  EXPECT_TRUE(std::filesystem::exists(root_ / "fwl_tbl_0"));
  EXPECT_EQ(CountVia(root_ / "fwl_tbl_0"), 3);
  EXPECT_FALSE(std::filesystem::exists(root_ / "fwl_counters_wan"));
}

TEST_F(TablePinReloadTest, ABundleThatDropsTheTableSweepsItsPin) {
  if (!BuildObject()) GTEST_SKIP() << "clang unavailable";
  // The policy stopped declaring the table. Its pin must not linger
  // in bpffs holding a dead policy's blocklist.
  Insert("10.0.0.0/8");
  WriteBundle(R"("conntrack", "fwl_nat")");
  auto report = ReconcilePinnedMaps(scratch_dir().string(),
                                    root_.string(), PinPolicy::kReload,
                                    0);
  EXPECT_NE(std::find(report.discarded.begin(), report.discarded.end(),
                      "fwl_tbl_0"),
            report.discarded.end());
  EXPECT_FALSE(std::filesystem::exists(root_ / "fwl_tbl_0"));
}

TEST_F(TablePinReloadTest, AnAdoptedTableIsStillReconciledToItsFile) {
  if (!BuildObject()) GTEST_SKIP() << "clang unavailable";
  // Adoption and disk authority together, which is the pair that
  // makes the id allocation safe without a registry: the trie keeps
  // its map object across the edit, and the sync then makes its
  // contents exactly the feed's. An entry that was in the old
  // contents and is not in the file does not survive.
  Insert("198.51.100.0/24");
  Insert("10.0.0.0/8");
  WriteBundle(R"("conntrack", "fwl_nat", "fwl_tbl_0")");
  ReconcilePinnedMaps(scratch_dir().string(), root_.string(),
                      PinPolicy::kReload, 0);
  ASSERT_TRUE(std::filesystem::exists(root_ / "fwl_tbl_0"));

  GeoipTrieEntry keep;
  keep.v6 = false;
  keep.prefixlen = 8;
  inet_pton(AF_INET, "10.0.0.0", keep.addr);
  auto synced = SyncTableTrie(trie_fd_, false, {keep});
  ASSERT_TRUE(synced.has_value()) << synced.error().message;
  EXPECT_EQ(synced->unchanged, 1u) << "10.0.0.0/8 was already there";
  EXPECT_EQ(synced->removed, 1u);
  EXPECT_EQ(CountVia(root_ / "fwl_tbl_0"), 1);
}

// --- A table survives a policy edit (MapLifetime.EXTERNAL) ---------

TEST(DecidePinFateTest, ATableTrieIsAdoptedAcrossAPolicyEdit) {
  // The phase-2 property, at the decision that makes it true. A
  // policy edit says nothing about whether an address is still
  // hostile, so the trie is not this compilation's to discard -- and
  // a table erased by every policy edit is not a table.
  //
  // The name is in `persistent` because the compiler put it there:
  // persistent_map_names() resolves the EXTERNAL registry row into
  // the literal fwl_tbl_<id> names the unit declares. fd compares
  // strings and re-derives nothing.
  const std::vector<std::string> persistent = {
      "conntrack", "fwl_nat", "fwl_tbl_0", "fwl_tbl_1"};
  PinnedMapShape trie;
  trie.type = BPF_MAP_TYPE_LPM_TRIE;
  trie.key_size = 8;
  trie.value_size = 1;
  trie.max_entries = 100000;
  trie.map_flags = BPF_F_NO_PREALLOC;
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(DecidePinFate("fwl_tbl_0", persistent, &trie, trie,
                            policy),
              PinVerdict::kAdopt);
  }
}

TEST(DecidePinFateTest, ATableTrieIsStillDroppedWhenCapacityMoves) {
  // Adoption is not unconditional. `max` is part of the declaration
  // an operator reviews, so raising it is a shape change libbpf will
  // refuse to reuse -- the state is unreachable either way and all
  // that is left to decide is who finds out. The contents are not
  // lost by this: they are on disk, and the next load reads them.
  const std::vector<std::string> persistent = {"fwl_tbl_0"};
  PinnedMapShape have;
  have.type = BPF_MAP_TYPE_LPM_TRIE;
  have.key_size = 8;
  have.value_size = 1;
  have.max_entries = 1000;
  have.map_flags = BPF_F_NO_PREALLOC;
  PinnedMapShape want = have;
  want.max_entries = 100000;
  EXPECT_NE(DecidePinFate("fwl_tbl_0", persistent, &want, have,
                          PinPolicy::kColdBoot),
            PinVerdict::kAdopt);
  EXPECT_NE(DecidePinFate("fwl_tbl_0", persistent, &want, have,
                          PinPolicy::kReload),
            PinVerdict::kAdopt);
}

TEST(DecidePinFateTest, ATablePinNoPolicyDeclaresIsSweptAway) {
  // The table was deleted from the policy. Nothing will read it,
  // nothing will reconcile it against a file, and it would sit in
  // bpffs holding a dead policy's blocklist until something with the
  // same id and shape adopted it. Dropping it is what makes an id
  // that shifted between compilations safe.
  const std::vector<std::string> persistent = {"fwl_tbl_0"};
  PinnedMapShape have;
  have.type = BPF_MAP_TYPE_LPM_TRIE;
  have.key_size = 8;
  have.value_size = 1;
  have.max_entries = 1000;
  have.map_flags = BPF_F_NO_PREALLOC;
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(DecidePinFate("fwl_tbl_0", persistent, nullptr, have,
                            policy),
              PinVerdict::kDiscard);
  }
}

TEST(DecidePinFateTest, ATableIsSweptWhenTheManifestDoesNotNameIt) {
  // A bundle compiled before tables existed, or one whose policy
  // declares none, carries a persistent list without any fwl_tbl_
  // name. The pin must go: `persistent` is the whole gate, and a
  // prefix-shaped exception in the daemon would be the second copy of
  // a decision this list exists to keep in one place.
  PinnedMapShape have;
  have.type = BPF_MAP_TYPE_LPM_TRIE;
  have.key_size = 8;
  have.value_size = 1;
  have.max_entries = 1000;
  have.map_flags = BPF_F_NO_PREALLOC;
  EXPECT_EQ(DecidePinFate("fwl_tbl_0", kPersistent, &have, have,
                          PinPolicy::kReload),
            PinVerdict::kDiscard);
}

TEST(DecidePinFateTest, ADevmapPinLeftByAnOlderBundleIsSweptAway) {
  // The upgrade path for the devmap reclassification, and the only
  // thing on the daemon side that change touches.
  //
  // Until it, `fwl_devmap_<dest>` carried LIBBPF_PIN_BY_NAME, so a box
  // that ran any redirecting policy has one in bpffs. A devmap cannot
  // be reused from a pin at all — the kernel forces BPF_F_RDONLY_PROG
  // in dev_map_alloc and libbpf's reuse check compares that against
  // the object's declared map_flags of 0 — which is why the emitter
  // stopped pinning them, and why the second inside zone of a gateway
  // could not load. Bundles compiled since declare no such pin, so
  // `declared` is null here, and the pin has to GO rather than be left
  // to accumulate: it holds ifindexes of a policy that is no longer
  // running, and nothing will ever overwrite it.
  //
  // Both paths, because a devmap pin outlives a process restart just
  // as it outlives a reload.
  auto have = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(DecidePinFate("fwl_devmap_wan", kPersistent, nullptr,
                            have, policy),
              PinVerdict::kDiscard);
  }
}

TEST(DecidePinFateTest, ALegacyNatCfgPinIsSweptAway) {
  // The upgrade path for the masquerade-source split.
  //
  // Until it, every zone object pinned one bundle-global `fwl_nat_cfg`,
  // so a box that ran any masquerading policy has one in bpffs. Bundles
  // compiled since pin `fwl_nat_cfg_<zone>` instead and declare that
  // name not at all, so `declared` is null here and the pin has to GO:
  // it holds the masquerade address of a policy that is no longer
  // running, and nothing will ever overwrite it.
  //
  // It costs nothing to discard, which is the whole reason the split is
  // safe. `fd` derives every slot from THIS bundle's redirect topology
  // and the live interface addresses at every load, so the value is
  // rewritten before the first packet either way.
  auto have = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(DecidePinFate("fwl_nat_cfg", kPersistent, nullptr,
                            have, policy),
              PinVerdict::kDiscard);
    // And the new name is policy-scoped too: slot 0 is derived at load
    // time, so a matching declaration must not rescue it either.
    EXPECT_EQ(DecidePinFate("fwl_nat_cfg_lan", kPersistent, &have,
                            have, policy),
              PinVerdict::kDiscard);
  }
}

TEST(NatCfgMapNamesTest, ThePerZoneNameIsPreferredAndTheOldOneRemains) {
  // The masquerade source is `fwl_nat_cfg_<zone>` because the address
  // is a per-zone fact: it is the address of the zone THIS one
  // redirects to, and two masquerading zones need not name the same
  // uplink. Under the old bundle-global name it was one kernel map
  // with one slot 0, written once per masquerading zone, so the last
  // zone loaded decided what every masquerading program translated to.
  //
  // The old name stays in the list, second, and dropping it would be
  // the failure `ManifestStatesMasquerade` documents one field over: a
  // bundle staged by an older `fwl` has only the bundle-global map, and
  // an `fd` that could not find it would turn every masquerade in that
  // bundle into a silent no-op across an upgrade the operator did not
  // ask for.
  auto names = NatCfgMapNames("ina");
  ASSERT_EQ(names.size(), 2u);
  EXPECT_EQ(names[0], "fwl_nat_cfg_ina");
  EXPECT_EQ(names[1], "fwl_nat_cfg");
}

TEST(NatCfgMapNamesTest, TwoZonesAskForTwoDifferentMaps) {
  // The property the whole change rests on, stated where a rename
  // cannot quietly undo it.
  EXPECT_NE(NatCfgMapNames("ina")[0], NatCfgMapNames("inb")[0]);
  EXPECT_EQ(NatCfgMapNames("ina")[1], NatCfgMapNames("inb")[1]);
}

TEST(DecidePinFateTest, AnUnknownNameIsDiscarded) {
  // The sweep is an allowlist of what survives, not a blocklist of
  // what goes. A map added to the emitter and forgotten here is
  // discarded — at worst that costs state that could have been kept.
  // The previous prefix-blocklist adopted it instead, which is the
  // silent-wrong direction and how this class of defect kept
  // recurring.
  auto shape = SomeShape();
  EXPECT_EQ(DecidePinFate("fwl_something_new", kPersistent, &shape,
                          shape, PinPolicy::kColdBoot),
            PinVerdict::kDiscard);
}

TEST(DefaultPersistentMapNamesTest, IsExactlyTheFlowKeyedPair) {
  // Used for bundles compiled before manifests carried
  // `persistent_maps`. Must equal emitter.persistent_map_names();
  // fwl/tests/unit/test_map_lifetime.py reads this source file and
  // fails if the registry and this list drift apart.
  EXPECT_EQ(DefaultPersistentMapNames(),
            (std::vector<std::string>{"conntrack", "fwl_nat"}));
}

TEST_F(BpfLoaderResolverTest, ManifestPersistentMapsAreRead) {
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","persistent_maps":["conntrack"]})";
  EXPECT_EQ(ReadPersistentMapNames(bundle.string()),
            (std::vector<std::string>{"conntrack"}));
}

TEST_F(BpfLoaderResolverTest, OlderManifestFallsBackRatherThanSweeping) {
  // A bundle compiled before this field existed. Reading "no
  // persistent maps" out of its silence would drop the conntrack table
  // on the first reload after a package upgrade — the exact outage the
  // mechanism exists to prevent.
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","zones":[],"programs":[]})";
  EXPECT_EQ(ReadPersistentMapNames(bundle.string()),
            DefaultPersistentMapNames());
}

TEST_F(BpfLoaderResolverTest, UnreadableManifestFallsBackToo) {
  EXPECT_EQ(ReadPersistentMapNames((scratch_ / "absent").string()),
            DefaultPersistentMapNames());
}

TEST_F(BpfLoaderResolverTest, ManifestNamesItsMasqueradeSources) {
  // Every object in a NAT bundle carries fwl_nat_cfg — the de-NAT pass
  // on the return path needs it — so the map's presence does not
  // identify a masquerade source. This flag does, and `false` here is
  // an answer, not a silence.
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","programs":[)"
         R"({"zone":"lan","masquerades":true},)"
         R"({"zone":"wan","masquerades":false}]})";
  EXPECT_TRUE(ManifestStatesMasquerade(bundle.string()));
}

TEST_F(BpfLoaderResolverTest, AManifestWithoutTheFlagAnswersNothing) {
  // Compiled before the field existed. Reading its silence as "no zone
  // masquerades" would seed no address at all, and the XDP masquerade
  // action no-ops on an unset slot: an `fd` upgrade would silently
  // stop translating a bundle it never recompiled. The loader falls
  // back to the old presence rule for these, which is what this
  // distinction is for.
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","programs":[{"zone":"lan"}]})";
  EXPECT_FALSE(ManifestStatesMasquerade(bundle.string()));
}

TEST_F(BpfLoaderResolverTest, AnAbsentManifestAnswersNothingEither) {
  EXPECT_FALSE(
      ManifestStatesMasquerade((scratch_ / "absent").string()));
}

// --- What the bundle asks to be attached, and where ------------------
//
// The manifest's "zones" array is not the answer on its own. A unit
// written in the simple form — `@xdp(eth0)`, no `zone` line, the form
// the docs teach and the first one anybody writes — declares no zones,
// so the array is `[]` while the program entry names `eth0`. Deriving
// interfaces from the array alone gave that bundle none, and the
// loader attached it to nothing and returned success: `fd` logged
// "1 zone program(s)", which was true of the program list and said
// nothing at all about attachment, while every packet on the box
// flowed unfiltered.

class BundlePlanTest : public BpfLoaderResolverTest {
 protected:
  auto Plan(const std::string& manifest) -> BundleAttachPlan {
    auto bundle = scratch_ / "bundle";
    fs::create_directories(bundle);
    std::ofstream(bundle / "manifest.json") << manifest;
    return PlanBundleAttach(bundle.string());
  }
};

TEST_F(BundlePlanTest, DeclaredZonesCarryTheirInterfaces) {
  auto plan = Plan(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lan0","lan1"]},
             {"name":"wan","interfaces":["wan0"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"},
                {"zone":"wan","object":"wan.bpf.o"}]})");
  EXPECT_EQ(plan.zone_interfaces["lan"],
            (std::vector<std::string>{"lan0", "lan1"}));
  EXPECT_EQ(plan.zone_interfaces["wan"],
            (std::vector<std::string>{"wan0"}));
  EXPECT_TRUE(plan.zones_without_interfaces.empty());
}

TEST_F(BundlePlanTest, TheSimpleFormNamesItsInterfaceInTheProgram) {
  // `@xdp(eth0)` with no zone declaration. FWL_V04_SPEC.md § 6.2:
  // "one implicit zone whose name is the @xdp argument"; the v0.1
  // spec spells the hook `@xdp(<interface>)`. So the zone name IS the
  // interface name, and a plan that comes back empty here is a
  // firewall that attaches to nothing.
  auto plan = Plan(R"({"version":"0.4","zones":[],
    "programs":[{"zone":"eth0","object":"eth0.bpf.o"}]})");
  EXPECT_EQ(plan.zone_interfaces["eth0"],
            (std::vector<std::string>{"eth0"}));
  EXPECT_TRUE(plan.zones_without_interfaces.empty());
}

TEST_F(BundlePlanTest, ARedirectOnlyZoneKeepsItsInterfaces) {
  // A declared zone with no @xdp block of its own is legal (v0.4
  // § 6.2) and is still a redirect destination — its interfaces are
  // what fills the destination devmap, so dropping it from the plan
  // would make every redirect into it drop the frame.
  auto plan = Plan(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lan0"]},
             {"name":"dmz","interfaces":["dmz0"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o",
                 "redirects_to":["dmz"]}]})");
  EXPECT_EQ(plan.zone_interfaces["dmz"],
            (std::vector<std::string>{"dmz0"}));
}

TEST_F(BundlePlanTest, AProgramZoneWithNoInterfacesIsReported) {
  // A declared zone the manifest gives an empty interface list. `fwl`
  // cannot emit this (the analyzer rejects an empty zone), which is
  // the point: it means the manifest and the compiler disagree, and
  // the program can never be attached to anything. That is a
  // different fact from "the NIC has not appeared yet" and must not
  // be reported as one.
  auto plan = Plan(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":[]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})");
  EXPECT_EQ(plan.zones_without_interfaces,
            (std::vector<std::string>{"lan"}));
}

TEST_F(BundlePlanTest, AnUnreadableManifestPlansNothing) {
  EXPECT_TRUE(
      PlanBundleAttach((scratch_ / "absent").string())
          .zone_interfaces.empty());
}

// --- Refusing a load that would attach to nothing ---------------------

class ZeroAttachTest : public BpfLoaderResolverTest {
 protected:
  // A bundle whose manifest is `manifest` and whose named objects
  // exist as files. The objects are not valid ELF: these tests must
  // fail BEFORE libbpf is reached, so reaching it at all is the
  // failure they detect.
  auto Load(const std::string& manifest,
            const std::vector<std::string>& objects)
      -> std::expected<ZoneBundleHandles, Error<BpfError>> {
    auto bundle = scratch_ / "bundle";
    fs::create_directories(bundle);
    std::ofstream(bundle / "manifest.json") << manifest;
    for (const auto& o : objects) {
      Touch(bundle / o);
    }
    return LoadZoneBundle(bundle.string(),
                          (scratch_ / "pins").string());
  }
};

TEST_F(ZeroAttachTest, NoInterfaceOnThisHostIsAFailedLoad) {
  // Every interface the bundle names is absent. Nothing can be
  // attached, so not one packet would be inspected — and a load that
  // returns success here hands `fd` a firewall that is not in the
  // path while every indicator reads healthy. The rule is about the
  // outcome, not the reason: zero interfaces attached is a failed
  // load however it came about.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["f-no-such-if0"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})",
                {"lan.bpf.o"});
  ASSERT_FALSE(r.has_value()) << "attached to nothing and said ok";
  EXPECT_EQ(r.error().code, BpfError::kAttachFailed);
  // Refused for the right reason, and early: had it got as far as
  // libbpf the message would be about opening a file that is not an
  // object. It must name the interface it wanted, too — an operator
  // reading this at 3am needs the typo, not a verdict.
  EXPECT_NE(r.error().message.find("f-no-such-if0"),
            std::string::npos)
      << r.error().message;
  EXPECT_NE(r.error().message.find("ZERO"), std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, TheSimpleFormIsRefusedForItsOwnInterface) {
  // The degenerate `@xdp(<iface>)` bundle, with an interface that
  // does not exist. Before the loader read the program's zone name as
  // an interface this could not even reach the refusal: the plan was
  // empty, the attach loop ran zero times, and the load succeeded.
  // Now it is the ordinary missing-interface case and says so.
  auto r = Load(R"({"version":"0.4","zones":[],
    "programs":[{"zone":"f-no-such-if1","object":"x.bpf.o"}]})",
                {"x.bpf.o"});
  ASSERT_FALSE(r.has_value()) << "attached to nothing and said ok";
  EXPECT_EQ(r.error().code, BpfError::kAttachFailed);
  EXPECT_NE(r.error().message.find("f-no-such-if1"),
            std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, AZoneProgramWithNoInterfaceAtAllIsRefused) {
  // Not a missing NIC — a manifest that names no interface for a
  // program at all. There is nothing to wait for, so it is refused
  // before any object is opened, with a message that says which zone.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":[]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})",
                {"lan.bpf.o"});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
  // The specific sentence, not merely "some error": the fake ELF in
  // this bundle would fail the load anyway, and a test satisfied by
  // that would pass without the check it exists to pin.
  EXPECT_NE(r.error().message.find("names no interface"),
            std::string::npos)
      << r.error().message;
  EXPECT_NE(r.error().message.find("lan"), std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, AnObjectlessBundleStillReportsItsOwnFault) {
  // The l8_01 case: no compiled object anywhere (clang unavailable at
  // compile time). The interface pre-flight must not steal this
  // message — nothing is attachable because nothing was compiled, and
  // that is what the operator has to fix.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lo"]}],
    "programs":[{"zone":"lan","object":null}]})",
                {});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
  EXPECT_NE(r.error().message.find("no loadable zone programs"),
            std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, APresentInterfaceGetsPastThePreflight) {
  // The control that keeps the tests above from passing for the wrong
  // reason. `lo` exists on every host, so the pre-flight must let this
  // through and the load must fail later, on the object — proving the
  // refusals above are about attachment and not about the fake ELF
  // every one of these bundles carries.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lo"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})",
                {"lan.bpf.o"});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().message.find("ZERO"), std::string::npos)
      << "pre-flight fired on a host that has `lo`: "
      << r.error().message;
}

TEST_F(BpfLoaderResolverTest, ReconcileOnAnAbsentPinRootIsQuiet) {
  // First boot, or bpffs freshly mounted. Nothing pinned, nothing to
  // reconcile, and no error either.
  auto report = ReconcilePinnedMaps((scratch_ / "bundle").string(),
                                    (scratch_ / "nopins").string(),
                                    PinPolicy::kColdBoot, 300);
  EXPECT_TRUE(report.discarded.empty());
  EXPECT_TRUE(report.adopted.empty());
  EXPECT_EQ(report.conntrack_swept, 0u);
}

}  // namespace
}  // namespace f
