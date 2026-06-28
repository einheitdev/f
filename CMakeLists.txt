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
# Engine library (BPF + ZMQ, no HTTP)
# ============================================================================
add_library(libf-engine STATIC
  src/bpf_loader.cc
  src/engine.cc
  src/slow_path.cc
  src/components.cc
)

target_include_directories(libf-engine PUBLIC
  ${PROJECT_SOURCE_DIR}/include
  ${BPF_INCLUDE_DIR}
  ${CMAKE_BINARY_DIR}
)

target_link_libraries(libf-engine PUBLIC
  ${BPF_LIB}
  nlohmann_json::nlohmann_json
  cppzmq
  spdlog::spdlog
  pthread
)

add_dependencies(libf-engine fw_skel)

# ============================================================================
# API library (Crow + pinned map reads, no BPF loading)
# ============================================================================
add_library(libf-api STATIC
  src/api.cc
  src/html.cc
)

target_include_directories(libf-api PUBLIC
  ${PROJECT_SOURCE_DIR}/include
  ${BPF_INCLUDE_DIR}
)

target_link_libraries(libf-api PUBLIC
  ${BPF_LIB}
  Crow::Crow
  nlohmann_json::nlohmann_json
  cppzmq
  spdlog::spdlog
  pthread
)

# ============================================================================
# fd — BPF engine daemon
# ============================================================================
add_executable(fd cmd/fd.cc)
target_link_libraries(fd PRIVATE
  libf-engine CLI11::CLI11)

# ============================================================================
# fctl — engine control CLI
# ============================================================================
add_executable(fctl cmd/fctl.cc)
target_include_directories(fctl PRIVATE
  ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(fctl PRIVATE
  libf-engine CLI11::CLI11)

# ============================================================================
# f-api — web dashboard daemon
# ============================================================================
add_executable(f-api cmd/f_api.cc)
target_link_libraries(f-api PRIVATE
  libf-api libf-engine CLI11::CLI11)

# ============================================================================
# einheit-cli framework (sibling repo)
# ============================================================================
set(EINHEIT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(EINHEIT_BUILD_ADAPTERS OFF CACHE BOOL "" FORCE)
add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../cli
  ${CMAKE_BINARY_DIR}/_deps/einheit-cli
  EXCLUDE_FROM_ALL
)

# ============================================================================
# einheit-ui framework (sibling repo)
# ============================================================================
set(EINHEIT_UI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(EINHEIT_UI_BUILD_ADAPTERS OFF CACHE BOOL "" FORCE)
set(EINHEIT_UI_BUILD_BINARY OFF CACHE BOOL "" FORCE)
add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../ui
  ${CMAKE_BINARY_DIR}/_deps/einheit-ui
  EXCLUDE_FROM_ALL
)

# ============================================================================
# f CLI adapter
# ============================================================================
add_subdirectory(adapters/cli)

# ============================================================================
# f UI adapter
# ============================================================================
add_subdirectory(adapters/ui)

# ============================================================================
# einheit-f — appliance CLI binary
# ============================================================================
add_executable(einheit-f cmd/einheit_f.cc)
target_link_libraries(einheit-f PRIVATE
  einheit_adapter_fw CLI11::CLI11)

# ============================================================================
# einheit-f-ui — appliance web UI binary
# ============================================================================
add_executable(einheit-f-ui cmd/einheit_f_ui.cc)
target_link_libraries(einheit-f-ui PRIVATE
  einheit_ui_adapter_fw CLI11::CLI11)
target_compile_definitions(einheit-f-ui PRIVATE
  EINHEIT_UI_TEMPLATES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../ui/templates"
  EINHEIT_UI_ASSETS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../ui/assets"
)

# ============================================================================
# Install rules
# ============================================================================
install(TARGETS fd fctl einheit-f einheit-f-ui f-api
  RUNTIME DESTINATION bin
)
install(FILES deploy/fd.yaml
  DESTINATION share/f
)
install(FILES
  deploy/systemd/fd.service
  deploy/systemd/einheit-f-ui.service
  deploy/systemd/f-firstboot.service
  DESTINATION lib/systemd/system
)
install(FILES
  deploy/networkd/10-eth0.network
  deploy/networkd/20-lan.network
  DESTINATION share/f/networkd
)
install(PROGRAMS deploy/firstboot/firstboot.sh
  DESTINATION share/f
)

# ============================================================================
# Tests
# ============================================================================
enable_testing()
add_subdirectory(tests)
include(CTest)
