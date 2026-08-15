/// @file sha256.h
/// @brief SHA-256, because the compiler and the box must agree.
///
/// The bundle manifest records the digest of the policy TEXT it was
/// compiled from, so a box can be asked whether the `.fw` on disk is
/// still the one in the packet path. That answer is only worth having
/// if both ends compute the same number, and the compiler is Python —
/// `hashlib.sha256`. This is the other half of that agreement.
///
/// Implemented here rather than linked, for the reason BUGLOG #52
/// records: a daemon on an appliance that depends on a shared object
/// is a daemon that stops running when the object moves. Sixty lines
/// with published test vectors cost less than a runtime dependency in
/// the packet-path binaries.

#ifndef INCLUDE_F_SHA256_H_
#define INCLUDE_F_SHA256_H_

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace f {

/// Lowercase hex SHA-256 of `data`.
auto Sha256Hex(std::string_view data) -> std::string;

/// Lowercase hex SHA-256 of a file's contents, or nullopt when the
/// file could not be read.
///
/// Nullopt rather than the digest of an empty string: "this file is
/// empty" and "this file could not be opened" are different findings,
/// and a comparison that treats the second as the first reports drift
/// on every box whose source is behind a permission bit.
auto Sha256File(const std::filesystem::path& path)
    -> std::optional<std::string>;

}  // namespace f

#endif  // INCLUDE_F_SHA256_H_
