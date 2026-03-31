include(GoogleTest)

file(GLOB_RECURSE test_sources
  CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cc"
)

foreach(test_source ${test_sources})
  get_filename_component(test_name ${test_source} NAME_WE)
  add_executable(${test_name} ${test_source})
  target_link_libraries(${test_name} PRIVATE
    libf-api
    libf-engine
    GTest::gtest_main
  )
  gtest_discover_tests(${test_name}
    DISCOVERY_TIMEOUT 10
    PROPERTIES TIMEOUT 30
  )
endforeach()
