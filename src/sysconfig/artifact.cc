/// @file artifact.cc
/// @brief Digest, drift detection and atomic install for derived files.

#include "f/sysconfig/artifact.h"

#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>

namespace f::sysconfig {
namespace {

constexpr const char* kDigestPrefix = "# model-digest: ";

auto Fnv1a64(const std::string& s) -> std::uint64_t {
  std::uint64_t h = 1469598103934665603ULL;
  for (unsigned char c : s) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  return h;
}

/// Split a digest-wrapped document into its declared digest and body.
/// Returns false when the document is not digest-wrapped at all.
auto SplitDigest(const std::string& doc, std::string* declared,
                 std::string* body) -> bool {
  const auto prefix = std::string(kDigestPrefix);
  if (doc.size() < prefix.size() ||
      doc.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }
  auto nl = doc.find('\n');
  if (nl == std::string::npos) return false;
  *declared = doc.substr(prefix.size(), nl - prefix.size());
  auto start = nl + 1;
  if (start < doc.size() && doc[start] == '\n') start++;
  *body = doc.substr(start);
  return true;
}

}  // namespace

auto DriftKindName(DriftKind k) -> std::string {
  switch (k) {
    case DriftKind::kAbsent:
      return "absent";
    case DriftKind::kHandEdited:
      return "hand-edited";
    case DriftKind::kStale:
      return "stale";
    case DriftKind::kNone:
      break;
  }
  return "none";
}

auto BodyDigest(const std::string& body) -> std::string {
  return std::format("{:016x}", Fnv1a64(body));
}

auto WrapWithDigest(const std::string& body) -> std::string {
  return std::format("{}{}\n\n{}", kDigestPrefix, BodyDigest(body),
                     body);
}

auto CheckArtifactDrift(const std::string& path,
                        const std::string& expected) -> DriftKind {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) return DriftKind::kAbsent;
  std::ifstream in(path);
  if (!in) return DriftKind::kAbsent;
  std::ostringstream ss;
  ss << in.rdbuf();
  auto on_disk = ss.str();

  std::string declared;
  std::string body;
  if (!SplitDigest(on_disk, &declared, &body)) {
    return DriftKind::kHandEdited;
  }
  if (BodyDigest(body) != declared) return DriftKind::kHandEdited;
  if (on_disk != expected) return DriftKind::kStale;
  return DriftKind::kNone;
}

auto ArtifactIsGenerated(const std::string& path) -> bool {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) return false;
  std::ifstream in(path);
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  std::string declared;
  std::string body;
  return SplitDigest(ss.str(), &declared, &body);
}

auto InstallArtifact(const std::string& path,
                     const std::string& content)
    -> std::expected<bool, std::string> {
  std::error_code ec;
  auto parent = std::filesystem::path(path).parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
  }

  if (std::filesystem::exists(path, ec)) {
    std::ifstream in(path);
    std::ostringstream ss;
    ss << in.rdbuf();
    if (ss.str() == content) return false;
  }

  auto tmp = path + ".tmp";
  {
    std::ofstream out(tmp);
    if (!out) return std::unexpected(std::format("cannot write {}", tmp));
    out << content;
    out.flush();
    if (!out.good()) {
      return std::unexpected(std::format("short write to {}", tmp));
    }
  }
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::error_code rm;
    std::filesystem::remove(tmp, rm);
    return std::unexpected(
        std::format("cannot install {}: {}", path, ec.message()));
  }
  return true;
}

}  // namespace f::sysconfig
