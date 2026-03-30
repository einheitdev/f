/// @file error.h
/// @brief Generic error template for std::expected returns.

#ifndef INCLUDE_F_ERROR_H_
#define INCLUDE_F_ERROR_H_

#include <expected>
#include <string>
#include <utility>

namespace f {

/// Generic error wrapper parameterized by an error code enum.
template <typename ErrorCodeEnum>
struct Error {
  ErrorCodeEnum code;
  std::string message;
};

/// Construct an Error<E> wrapped in std::unexpected.
template <typename E>
auto MakeError(E code, std::string message)
    -> std::unexpected<Error<E>> {
  return std::unexpected(
      Error<E>{code, std::move(message)});
}

}  // namespace f

#endif  // INCLUDE_F_ERROR_H_
