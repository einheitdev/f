include(GoogleTest)

file(GLOB_RECURSE test_sources
  CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cc"
)

foreach(test_source ${test_sources})
  get_filename_component(test_name ${test_source} NAME_WE)
  add_executable(${test_name} ${test_source})
  if(test_name MATCHES "^test_fw_")
    target_link_libraries(${test_name} PRIVATE
      einheit_adapter_fw
      GTest::gtest_main
    )
  elseif(test_name MATCHES "^test_ui_")
    target_link_libraries(${test_name} PRIVATE
      einheit_ui_adapter_fw_views
      GTest::gtest_main
    )
  elseif(test_name MATCHES "^test_sysconfig")
    target_link_libraries(${test_name} PRIVATE
      libf-sysconfig
      GTest::gtest_main
    )
  elseif(test_name MATCHES "^test_policy")
    target_link_libraries(${test_name} PRIVATE
      libf-policy
      GTest::gtest_main
    )
  elseif(test_name MATCHES "^test_lease")
    target_link_libraries(${test_name} PRIVATE
      libf-lease
      GTest::gtest_main
    )
  elseif(test_name MATCHES "^test_confd")
    target_link_libraries(${test_name} PRIVATE
      libf-confd
      GTest::gtest_main
    )
  else()
    target_link_libraries(${test_name} PRIVATE
      libf-engine
      GTest::gtest_main
    )
  endif()
  # The apply path owns the lifecycle of the units the model implies,
  # so anything that drives an apply needs a systemd to drive. This is
  # a fake systemctl that keeps a real unit table on disk: a test can
  # start it from `stopped` and prove the transition, which a stub that
  # answers the same thing before and after cannot.
  target_compile_definitions(${test_name} PRIVATE
    F_FAKE_SYSTEMCTL="${CMAKE_CURRENT_SOURCE_DIR}/support/fake_systemctl.py"
  )
  if(NOT CMAKE_CROSSCOMPILING)
    gtest_discover_tests(${test_name}
      DISCOVERY_TIMEOUT 10
      PROPERTIES TIMEOUT 30
    )
  endif()
endforeach()

# The page test renders the real .inja files, so it needs the template
# engine and the directory the adapter ships. A view model that keeps
# the four kinds of empty apart and a template that draws all four as
# an empty table is still a blank screen; only rendering catches that.
if(TARGET test_ui_pages)
  target_link_libraries(test_ui_pages PRIVATE ui_render)
  target_compile_definitions(test_ui_pages PRIVATE
    FW_TEMPLATES_DIR="${PROJECT_SOURCE_DIR}/adapters/ui/templates"
  )
endif()
