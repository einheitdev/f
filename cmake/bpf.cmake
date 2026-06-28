# BPF compilation: .bpf.c → .bpf.o → .skel.h
#
# BPF bytecode is architecture-independent. The clang invocation
# always uses `-target bpf` and runs on the BUILD host, not the
# cross-compilation target. The __TARGET_ARCH_* define tells the
# BPF program which kernel headers to reference for struct layouts
# (they match the TARGET, not the host).

find_program(BPFTOOL bpftool)

# Compile a BPF C source to an object and generate a skeleton header.
#
# Usage: add_bpf_object(<name> <source>)
# Creates target <name>_skel that produces <name>.skel.h in
# CMAKE_BINARY_DIR.
function(add_bpf_object name source)
  if(NOT BPFTOOL)
    message(WARNING
      "bpftool not found — BPF skeleton generation disabled. "
      "Install bpftool to enable BPF compilation.")
    # Create a stub skeleton header so the build can proceed.
    file(WRITE ${CMAKE_BINARY_DIR}/${name}.skel.h
      "// Stub — bpftool not available at configure time.\n"
      "#pragma once\n"
    )
    add_custom_target(${name}_skel)
    return()
  endif()

  set(BPF_OBJ ${CMAKE_BINARY_DIR}/${name}.bpf.o)
  set(BPF_SKEL ${CMAKE_BINARY_DIR}/${name}.skel.h)

  # Pick the right __TARGET_ARCH and system include path
  # based on the target platform (not the build host).
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(_bpf_arch_def "-D__TARGET_ARCH_arm64")
    set(_bpf_sys_inc "/usr/include/aarch64-linux-gnu")
  else()
    set(_bpf_arch_def "-D__TARGET_ARCH_x86")
    set(_bpf_sys_inc "/usr/include/x86_64-linux-gnu")
  endif()

  add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang -g -O2 -target bpf
      ${_bpf_arch_def} -D__BPF__
      -I${CMAKE_SOURCE_DIR}/include
      -I${BPF_INCLUDE_DIR}
      -I${_bpf_sys_inc}
      -c ${CMAKE_SOURCE_DIR}/${source}
      -o ${BPF_OBJ}
    DEPENDS
      ${CMAKE_SOURCE_DIR}/${source}
      ${CMAKE_SOURCE_DIR}/include/f/types.h
    COMMENT "BPF: ${source} -> ${name}.bpf.o"
  )

  add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND ${BPFTOOL} gen skeleton ${BPF_OBJ}
      > ${BPF_SKEL}
    DEPENDS ${BPF_OBJ}
    COMMENT "BPF skeleton: ${name}.skel.h"
  )

  add_custom_target(${name}_skel DEPENDS ${BPF_SKEL})
endfunction()
