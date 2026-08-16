/// @file neigh_mgr.cc
/// @brief Draining the datapath's unresolved next hops into the kernel.

#include "f/neigh_mgr.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <string>
#include <utility>
#include <vector>

#include <bpf/bpf.h>
#include <spdlog/spdlog.h>

namespace f {

namespace {

/// The datapath's key, byte for byte as the emitter declares it
/// (`struct fwl_nexthop` in emitter._ROUTE_DECL). Duplicated here
/// because a BPF map key has no header to share; the shape is pinned by
/// `NeighWantedKeyMatchesTheEmitter` in tests/test_neigh_mgr.cc, which
/// reads the emitter's own declaration.
struct WantedKey {
  uint32_t ifindex;
  uint32_t addr;
};

/// The states `bpf_fib_lookup` will accept a dmac from. Kept as the
/// kernel's own NUD_VALID rather than as "REACHABLE or STALE": a next
/// hop in PROBE or DELAY routes perfectly well, and calling it
/// unresolved would have this daemon soliciting an address that is
/// already working.
constexpr uint16_t kNudValid = NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE |
                               NUD_PROBE | NUD_STALE | NUD_DELAY;

/// One rtnetlink socket, used for both the question and the request.
class NetlinkNeigh : public NeighKernel {
 public:
  NetlinkNeigh() {
    fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd_ < 0) {
      spdlog::error(
          "next hop: could not open a netlink socket ({}). This box "
          "cannot resolve its own next hops and a masquerading policy "
          "will not forward until something else on it does.",
          ::strerror(errno));
      return;
    }
    struct sockaddr_nl local {};
    local.nl_family = AF_NETLINK;
    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&local),
               sizeof(local)) != 0) {
      spdlog::error("next hop: netlink bind failed ({})",
                    ::strerror(errno));
      ::close(fd_);
      fd_ = -1;
    }
  }

  ~NetlinkNeigh() override {
    if (fd_ >= 0) ::close(fd_);
  }

  NetlinkNeigh(const NetlinkNeigh&) = delete;
  auto operator=(const NetlinkNeigh&) -> NetlinkNeigh& = delete;

  auto State(const NextHop& nh) -> NeighState override {
    if (fd_ < 0) return NeighState::kAbsent;
    struct {
      struct nlmsghdr nlh;
      struct ndmsg ndm;
    } req {};
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ndm));
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = ++seq_;
    req.ndm.ndm_family = AF_INET;
    if (!Send(&req, req.nlh.nlmsg_len)) return NeighState::kAbsent;

    // The dump is filtered here rather than in the kernel: the ifindex
    // filter in RTM_GETNEIGH has moved between kernel versions, and a
    // filter the kernel silently ignores would answer this question for
    // the wrong interface. A neighbour table has tens of entries.
    NeighState found = NeighState::kAbsent;
    bool done = false;
    while (!done) {
      char buf[8192];
      ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n <= 0) break;
      for (struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(buf);
           NLMSG_OK(nlh, static_cast<unsigned int>(n));
           nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_DONE) {
          done = true;
          break;
        }
        if (nlh->nlmsg_type == NLMSG_ERROR) {
          done = true;
          break;
        }
        if (nlh->nlmsg_type != RTM_NEWNEIGH) continue;
        auto* ndm = static_cast<struct ndmsg*>(NLMSG_DATA(nlh));
        if (ndm->ndm_family != AF_INET) continue;
        if (ndm->ndm_ifindex != nh.ifindex) continue;
        int len = static_cast<int>(nlh->nlmsg_len) -
                  static_cast<int>(NLMSG_LENGTH(sizeof(*ndm)));
        for (struct rtattr* rta = RTM_RTA(ndm); RTA_OK(rta, len);
             rta = RTA_NEXT(rta, len)) {
          if (rta->rta_type != NDA_DST) continue;
          if (RTA_PAYLOAD(rta) != sizeof(uint32_t)) continue;
          uint32_t addr = 0;
          std::memcpy(&addr, RTA_DATA(rta), sizeof(addr));
          if (addr != nh.addr_be) continue;
          found = (ndm->ndm_state & kNudValid) != 0
                      ? NeighState::kUsable
                      : NeighState::kIncomplete;
        }
      }
    }
    return found;
  }

  auto Solicit(const NextHop& nh)
      -> std::expected<void, std::string> override {
    if (fd_ < 0) {
      return std::unexpected("no netlink socket");
    }
    struct {
      struct nlmsghdr nlh;
      struct ndmsg ndm;
      char attrs[RTA_LENGTH(sizeof(uint32_t))];
    } req {};
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ndm));
    req.nlh.nlmsg_type = RTM_NEWNEIGH;
    // CREATE so the first ask makes the entry, REPLACE so an existing
    // one is not an -EEXIST, ACK so a refusal is reported rather than
    // assumed away.
    req.nlh.nlmsg_flags =
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    req.nlh.nlmsg_seq = ++seq_;
    req.ndm.ndm_family = AF_INET;
    req.ndm.ndm_ifindex = nh.ifindex;
    req.ndm.ndm_state = NUD_NONE;
    // The whole request. With NTF_USE the kernel runs
    // `neigh_event_send()` and returns — it does not write a state, and
    // it does not take a link-layer address from us. We are asking it to
    // resolve, not telling it an answer, and a daemon that told the
    // kernel a MAC would be inventing routing.
    req.ndm.ndm_flags = NTF_USE;

    auto* rta = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<char*>(&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = NDA_DST;
    rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
    std::memcpy(RTA_DATA(rta), &nh.addr_be, sizeof(nh.addr_be));
    req.nlh.nlmsg_len =
        NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(sizeof(uint32_t));

    if (!Send(&req, req.nlh.nlmsg_len)) {
      return std::unexpected(
          std::format("netlink send failed: {}", ::strerror(errno)));
    }
    char buf[4096];
    ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
    if (n < 0) {
      return std::unexpected(
          std::format("netlink recv failed: {}", ::strerror(errno)));
    }
    auto* nlh = reinterpret_cast<struct nlmsghdr*>(buf);
    if (NLMSG_OK(nlh, static_cast<unsigned int>(n)) &&
        nlh->nlmsg_type == NLMSG_ERROR) {
      auto* err = static_cast<struct nlmsgerr*>(NLMSG_DATA(nlh));
      if (err->error != 0) {
        return std::unexpected(std::string(::strerror(-err->error)));
      }
    }
    return {};
  }

 private:
  auto Send(const void* msg, uint32_t len) -> bool {
    struct sockaddr_nl kernel {};
    kernel.nl_family = AF_NETLINK;
    return ::sendto(fd_, msg, len, 0,
                    reinterpret_cast<struct sockaddr*>(&kernel),
                    sizeof(kernel)) >= 0;
  }

  int fd_ = -1;
  uint32_t seq_ = 0;
};

/// The live `fwl_neigh_wanted` map.
class BpfNeighWanted : public NeighWanted {
 public:
  explicit BpfNeighWanted(int map_fd) : fd_(map_fd) {}

  auto Entries() -> std::vector<std::pair<NextHop, uint64_t>> override {
    std::vector<std::pair<NextHop, uint64_t>> out;
    if (fd_ < 0) return out;
    WantedKey key {};
    WantedKey next {};
    bool have = bpf_map_get_next_key(fd_, nullptr, &next) == 0;
    while (have) {
      key = next;
      uint64_t when = 0;
      if (bpf_map_lookup_elem(fd_, &key, &when) == 0) {
        out.push_back(
            {NextHop{static_cast<int>(key.ifindex), key.addr}, when});
      }
      have = bpf_map_get_next_key(fd_, &key, &next) == 0;
    }
    return out;
  }

  auto Forget(const NextHop& nh) -> void override {
    if (fd_ < 0) return;
    WantedKey key{static_cast<uint32_t>(nh.ifindex), nh.addr_be};
    bpf_map_delete_elem(fd_, &key);
  }

 private:
  int fd_ = -1;
};

}  // namespace

auto NextHopAddrString(uint32_t addr_be) -> std::string {
  char buf[INET_ADDRSTRLEN] = {};
  struct in_addr a {};
  a.s_addr = addr_be;
  if (::inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr) {
    return "?";
  }
  return buf;
}

auto MakeNetlinkNeighKernel() -> std::unique_ptr<NeighKernel> {
  return std::make_unique<NetlinkNeigh>();
}

auto MakeBpfNeighWanted(int map_fd) -> std::unique_ptr<NeighWanted> {
  return std::make_unique<BpfNeighWanted>(map_fd);
}

auto NeighMgr::OnDatapath(int ifindex) const -> bool {
  return std::find(datapath_ifindexes.begin(), datapath_ifindexes.end(),
                   ifindex) != datapath_ifindexes.end();
}

auto NeighMgr::MaybeResolve(uint64_t now_ns) -> void {
  if (!enabled) return;
  if (last_drain_ns != 0 &&
      now_ns - last_drain_ns < drain_interval_ms * 1000000ULL) {
    return;
  }
  last_drain_ns = now_ns;
  Resolve(now_ns);
}

auto NeighMgr::Resolve(uint64_t now_ns) -> void {
  if (wanted == nullptr || kernel == nullptr) return;
  std::vector<NextHop> still_out;
  for (const auto& [nh, wanted_at_ns] : wanted->Entries()) {
    // Bound (2). Unreachable through the datapath, which only records a
    // next hop out of the interface its own redirect named — so if this
    // ever fires, something upstream of here has changed and the
    // interesting thing is that it is SAID rather than that it is
    // handled. The management port is the reason it is a hard gate and
    // not an assertion: this daemon may not put ARP on the wire an
    // operator SSHes over because a map had an unexpected row in it.
    if (!OnDatapath(nh.ifindex)) {
      off_datapath++;
      wanted->Forget(nh);
      if (!reported[nh]) {
        reported[nh] = true;
        spdlog::error(
            "next hop: the datapath recorded {} on ifindex {}, which "
            "is not an interface this bundle is attached to. NOT "
            "resolving it — fd only solicits next hops out of the "
            "interfaces it has an XDP program on.",
            NextHopAddrString(nh.addr_be), nh.ifindex);
      }
      continue;
    }

    NeighState state = kernel->State(nh);
    if (state == NeighState::kUsable) {
      // Done: the datapath's next lookup for this hop returns a dmac.
      // The entry goes, so a hop that resolves costs one solicitation
      // and not a permanent row in this daemon's attention.
      resolved++;
      wanted->Forget(nh);
      last_solicit_ns.erase(nh);
      if (reported[nh]) {
        spdlog::info(
            "next hop: {} on ifindex {} is resolved; forwards through "
            "it are addressed again.",
            NextHopAddrString(nh.addr_be), nh.ifindex);
      }
      reported.erase(nh);
      continue;
    }

    // A next hop the datapath has stopped asking about. Keeping it
    // would have this daemon soliciting an address no loaded policy
    // routes to, which is exactly the thing bound (1) exists to stop.
    if (wanted_at_ns != 0 && now_ns > wanted_at_ns &&
        now_ns - wanted_at_ns > stale_after_s * 1000000000ULL) {
      forgotten_stale++;
      wanted->Forget(nh);
      last_solicit_ns.erase(nh);
      reported.erase(nh);
      continue;
    }

    still_out.push_back(nh);

    auto last = last_solicit_ns.find(nh);
    if (last != last_solicit_ns.end() &&
        now_ns - last->second < solicit_interval_s * 1000000000ULL) {
      continue;
    }
    last_solicit_ns[nh] = now_ns;
    auto asked = kernel->Solicit(nh);
    if (!asked) {
      failed++;
      if (!reported[nh]) {
        reported[nh] = true;
        spdlog::error(
            "next hop: could not ask the kernel to resolve {} on "
            "ifindex {} ({}). Forwards to it stay unaddressed.",
            NextHopAddrString(nh.addr_be), nh.ifindex, asked.error());
      }
      continue;
    }
    solicited++;
    if (state == NeighState::kAbsent && !reported[nh]) {
      // The first ask for a hop with no entry of any kind — which is
      // the measured state of a box that has just rebooted, and the one
      // that used to be permanent. Info, not a warning: this is the
      // daemon doing its job, and the warning belongs to the case where
      // it keeps having to.
      reported[nh] = true;
      spdlog::info(
          "next hop: the datapath could not address a forward to {} on "
          "ifindex {} and this box holds no neighbour entry for it, so "
          "the stack was never going to ARP for it — a translated frame "
          "is a martian to it. Asked the kernel to resolve it.",
          NextHopAddrString(nh.addr_be), nh.ifindex);
    }
  }
  outstanding = std::move(still_out);
}

auto NeighMgr::GetState() const -> nlohmann::json {
  auto arr = nlohmann::json::array();
  for (const auto& nh : outstanding) {
    arr.push_back({{"address", NextHopAddrString(nh.addr_be)},
                   {"ifindex", nh.ifindex}});
  }
  return {
      {"enabled", enabled},
      {"solicited", solicited},
      {"resolved", resolved},
      {"failed", failed},
      {"off_datapath", off_datapath},
      {"forgotten_stale", forgotten_stale},
      // The addresses, not just how many. A box that is asking and not
      // being answered has a wiring fault, and "1 unresolved" sends the
      // operator to look for it while "10.10.2.2 on enp0s4" tells them
      // which cable.
      {"unresolved", arr},
  };
}

auto NeighMgr::SetState(const nlohmann::json&) -> bool { return true; }

}  // namespace f
