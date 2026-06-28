## CMake toolchain file for aarch64-linux-gnu cross-compilation.
##
## Prerequisites (Debian/Ubuntu multiarch):
##   sudo dpkg --add-architecture arm64
##   sudo apt update
##   sudo apt install -y \
##     gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
##     libbpf-dev:arm64 libzmq3-dev:arm64 \
##     libelf-dev:arm64 libsodium-dev:arm64 \
##     libyaml-cpp-dev:arm64 libreadline-dev:arm64 \
##     zlib1g-dev:arm64

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

set(CMAKE_FIND_ROOT_PATH
  /usr/aarch64-linux-gnu
  /usr
)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

set(CMAKE_LIBRARY_PATH
  /usr/lib/aarch64-linux-gnu
  /usr/aarch64-linux-gnu/lib
)

set(CMAKE_INCLUDE_PATH
  /usr/include/aarch64-linux-gnu
  /usr/aarch64-linux-gnu/include
  /usr/include
)

set(PKG_CONFIG_EXECUTABLE /usr/bin/pkg-config)
set(ENV{PKG_CONFIG_PATH}
  "/usr/lib/aarch64-linux-gnu/pkgconfig")
set(ENV{PKG_CONFIG_LIBDIR}
  "/usr/lib/aarch64-linux-gnu/pkgconfig")
