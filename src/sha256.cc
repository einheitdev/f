/// @file sha256.cc
/// @brief FIPS 180-4 SHA-256.

#include "f/sha256.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>

namespace f {
namespace {

constexpr std::array<uint32_t, 64> kK = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

auto Ror(uint32_t x, int n) -> uint32_t {
  return (x >> n) | (x << (32 - n));
}

/// One 64-byte block into the running state.
void Compress(std::array<uint32_t, 8>* h, const unsigned char* block) {
  std::array<uint32_t, 64> w{};
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
           (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<uint32_t>(block[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = Ror(w[i - 15], 7) ^ Ror(w[i - 15], 18) ^
                  (w[i - 15] >> 3);
    uint32_t s1 = Ror(w[i - 2], 17) ^ Ror(w[i - 2], 19) ^
                  (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  auto s = *h;
  for (int i = 0; i < 64; ++i) {
    uint32_t s1 = Ror(s[4], 6) ^ Ror(s[4], 11) ^ Ror(s[4], 25);
    uint32_t ch = (s[4] & s[5]) ^ (~s[4] & s[6]);
    uint32_t t1 = s[7] + s1 + ch + kK[i] + w[i];
    uint32_t s0 = Ror(s[0], 2) ^ Ror(s[0], 13) ^ Ror(s[0], 22);
    uint32_t maj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
    uint32_t t2 = s0 + maj;
    s[7] = s[6];
    s[6] = s[5];
    s[5] = s[4];
    s[4] = s[3] + t1;
    s[3] = s[2];
    s[2] = s[1];
    s[1] = s[0];
    s[0] = t1 + t2;
  }
  for (int i = 0; i < 8; ++i) (*h)[i] += s[i];
}

}  // namespace

auto Sha256Hex(std::string_view data) -> std::string {
  std::array<uint32_t, 8> h = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                               0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                               0x1f83d9abu, 0x5be0cd19u};
  const auto* p = reinterpret_cast<const unsigned char*>(data.data());
  const size_t n = data.size();
  size_t off = 0;
  for (; off + 64 <= n; off += 64) Compress(&h, p + off);

  // The tail: the remainder, 0x80, zero padding, and the length in
  // bits as a big-endian u64. Two blocks when the remainder leaves no
  // room for the length.
  unsigned char tail[128] = {};
  const size_t rem = n - off;
  if (rem > 0) std::memcpy(tail, p + off, rem);
  tail[rem] = 0x80;
  const size_t tail_len = (rem >= 56) ? 128 : 64;
  const uint64_t bits = static_cast<uint64_t>(n) * 8;
  for (int i = 0; i < 8; ++i) {
    tail[tail_len - 1 - i] =
        static_cast<unsigned char>((bits >> (8 * i)) & 0xFF);
  }
  for (size_t i = 0; i < tail_len; i += 64) Compress(&h, tail + i);

  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (uint32_t word : h) {
    for (int shift = 28; shift >= 0; shift -= 4) {
      out.push_back(kHex[(word >> shift) & 0xF]);
    }
  }
  return out;
}

auto Sha256File(const std::filesystem::path& path)
    -> std::optional<std::string> {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;
  std::ostringstream ss;
  ss << in.rdbuf();
  if (in.bad()) return std::nullopt;
  return Sha256Hex(ss.str());
}

}  // namespace f
