cmake_minimum_required(VERSION 3.20...4.20)

# ============================================================================
# Compiler Selection — MUST be before project()
# ============================================================================
if(NOT CMAKE_CROSSCOMPILING
    AND NOT DEFINED CMAKE_C_COMPILER
    AND NOT DEFINED CMAKE_CXX_COMPILER)
  find_program(_clang clang)
  find_program(_clangpp clang++)
  if(_clang AND _clangpp)
    set(CMAKE_C_COMPILER "${_clang}"
      CACHE FILEPATH "C compiler" FORCE)
    set(CMAKE_CXX_COMPILER "${_clangpp}"
      CACHE FILEPATH "C++ compiler" FORCE)
  endif()
  unset(_clang CACHE)
  unset(_clangpp CACHE)
endif()

project(f
  LANGUAGES C CXX
  DESCRIPTION "eBPF firewall"
  VERSION 0.1.0
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Detect and select fastest available ELF linker.
if(UNIX)
  set(_found_linker FALSE)
  foreach(_ld mold lld gold)
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env LC_ALL=C which ${_ld}
      OUTPUT_VARIABLE _path
      RESULT_VARIABLE _res
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    if(_res EQUAL 0 AND _path)
      execute_process(
        COMMAND "${_path}" --version
        RESULT_VARIABLE _ld_works
        OUTPUT_QUIET ERROR_QUIET
      )
      if(_ld_works EQUAL 0)
        message(STATUS "Using linker: ${_ld} at ${_path}")
        set(CMAKE_EXE_LINKER_FLAGS
            "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=${_ld}")
        set(CMAKE_SHARED_LINKER_FLAGS
            "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=${_ld}")
        set(CMAKE_MODULE_LINKER_FLAGS
            "${CMAKE_MODULE_LINKER_FLAGS} -fuse-ld=${_ld}")
        set(_found_linker TRUE)
        break()
      endif()
    endif()
  endforeach()

  if(NOT _found_linker)
    message(STATUS
      "No mold/lld/gold found; using default ld with "
      "-Wl,--start-group")
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -Wl,--start-group")
  endif()
endif()

# Debug flags.
if(CMAKE_BUILD_TYPE MATCHES Debug)
  message(STATUS "Debug mode — adding debug flags.")
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS_DEBUG
        "${CMAKE_C_FLAGS_DEBUG} -O0 -g -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS_DEBUG
        "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -fno-omit-frame-pointer")
    find_program(LLDB_EXECUTABLE lldb)
    if(LLDB_EXECUTABLE)
      set(CMAKE_C_FLAGS_DEBUG
          "${CMAKE_C_FLAGS_DEBUG} -glldb")
      set(CMAKE_CXX_FLAGS_DEBUG
          "${CMAKE_CXX_FLAGS_DEBUG} -glldb")
      message(STATUS "LLDB detected — adding -glldb.")
    endif()
  endif()
endif()

message(STATUS "Build system: ${CMAKE_GENERATOR}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER}")

# ============================================================================
# System dependencies
# ============================================================================
find_library(BPF_LIB bpf REQUIRED)
find_path(BPF_INCLUDE_DIR bpf/libbpf.h REQUIRED)
message(STATUS "libbpf: ${BPF_LIB}")
message(STATUS "libbpf headers: ${BPF_INCLUDE_DIR}")

# ============================================================================
# FetchContent dependencies + BPF compile rules
# ============================================================================
include("cmake/deps.cmake")
include("cmake/bpf.cmake")

# ============================================================================
# BPF program
# ============================================================================
add_bpf_object(fw bpf/fw.bpf.c)

# ============================================================================
# Library: libf
# ============================================================================
add_library(libf STATIC
  src/bpf_loader.cc
  src/daemon.cc
  src/html.cc
  src/api.cc
)

set_target_properties(libf PROPERTIES OUTPUT_NAME f)

target_include_directories(libf PUBLIC
  ${PROJECT_SOURCE_DIR}/include
  ${BPF_INCLUDE_DIR}
  ${CMAKE_BINARY_DIR}
)

target_link_libraries(libf PUBLIC
  ${BPF_LIB}
  spdlog::spdlog
  Crow::Crow
  nlohmann_json::nlohmann_json
  cppzmq
  pthread
)

add_dependencies(libf fw_skel)

# ============================================================================
# Executable: fd
# ============================================================================
add_executable(fd src/main.cc)

target_link_libraries(fd PRIVATE
  libf
  CLI11::CLI11
)

# ============================================================================
# Tailwind CSS (optional)
# ============================================================================
find_program(TAILWINDCSS tailwindcss)
if(TAILWINDCSS)
  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/ui/style.css
    COMMAND ${TAILWINDCSS}
      -i ${CMAKE_SOURCE_DIR}/ui/input.css
      -o ${CMAKE_BINARY_DIR}/ui/style.css
      --minify
    DEPENDS ui/input.css ui/index.html
    COMMENT "Tailwind CSS"
  )
  add_custom_target(tailwind ALL
    DEPENDS ${CMAKE_BINARY_DIR}/ui/style.css)
endif()

# ============================================================================
# Tests
# ============================================================================
enable_testing()
add_subdirectory(tests)
include(CTest)
