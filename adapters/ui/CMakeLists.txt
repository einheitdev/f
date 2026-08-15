# The judgement the pages make about fd's answers, with no Crow and no
# libbpf behind it, so every decision is reachable from a unit test.
# The inside of a route handler is not: the removed `/counters` page
# was wrong on every box ever deployed and no test could see it,
# because there was nothing to call.
add_library(einheit_ui_adapter_fw_views STATIC
  src/views.cc
)

target_include_directories(einheit_ui_adapter_fw_views PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(einheit_ui_adapter_fw_views PUBLIC
  libf-counters
  libf-rules
  nlohmann_json::nlohmann_json
)

add_library(einheit_ui_adapter_fw STATIC
  src/ui_adapter.cc
)

target_include_directories(einheit_ui_adapter_fw PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(einheit_ui_adapter_fw PUBLIC
  einheit_ui
  einheit_ui_adapter_fw_views
  libf-engine
  nlohmann_json::nlohmann_json
)

target_compile_definitions(einheit_ui_adapter_fw PRIVATE
  EINHEIT_UI_ADAPTER_FW_TEMPLATES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/templates"
)

install(
  DIRECTORY templates/
  DESTINATION share/einheit-ui/adapters/fw/templates
  FILES_MATCHING PATTERN "*.inja"
)
