add_library(einheit_adapter_fw STATIC
  src/adapter.cc
  src/transport.cc
)

target_include_directories(einheit_adapter_fw PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(einheit_adapter_fw PUBLIC
  einheit_cli
  libf-sysconfig
  libf-lease
  libf-policy
  # The candidate-key contract shared with f-confd: the CLI names the
  # revision, the daemon applies it.
  libf-confd
  nlohmann_json::nlohmann_json
  cppzmq
)
