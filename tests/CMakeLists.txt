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
      libf-api
      libf-engine
      GTest::gtest_main
    )
  endif()
  if(NOT CMAKE_CROSSCOMPILING)
    gtest_discover_tests(${test_name}
      DISCOVERY_TIMEOUT 10
      PROPERTIES TIMEOUT 30
    )
  endif()
endforeach()
