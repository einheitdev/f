include(FetchContent)

# ----- spdlog (static, deliberately) -----------------------------------------
#
# It was shared, and the shared object lived in the build tree. Nothing
# installed it, because it is not a file anybody wrote — so `fd` on a
# real box died with
#
#   error while loading shared libraries: libspdlog.so.1.16
#
# at exec, before a single line of its own logging. A FetchContent
# dependency has no packaged home on the target: either it is linked
# in, or the deployable set has to carry a versioned .so and keep it
# in step with the binaries. Linking it in is the answer that cannot
# drift.
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(SPDLOG_NO_EXCEPTIONS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.16.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(spdlog)

if(NOT TARGET spdlog::spdlog)
  message(FATAL_ERROR "spdlog target missing.")
endif()

# ----- Crow (no SSL) ---------------------------------------------------------
set(CROW_ENABLE_SSL OFF CACHE BOOL "" FORCE)
set(CROW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CROW_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_TAG v1.3.0.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(crow)

if(TARGET Crow::Crow)
  # OK
elseif(TARGET Crow)
  add_library(Crow::Crow ALIAS Crow)
else()
  message(FATAL_ERROR "Crow target missing.")
endif()

# ----- nlohmann_json ---------------------------------------------------------
FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

if(NOT TARGET nlohmann_json::nlohmann_json)
  message(FATAL_ERROR "nlohmann_json target missing.")
endif()

# ----- CLI11 -----------------------------------------------------------------
FetchContent_Declare(cli11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG v2.6.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(cli11)

if(TARGET CLI11::CLI11)
  # OK
elseif(TARGET CLI11)
  add_library(CLI11::CLI11 ALIAS CLI11)
else()
  message(FATAL_ERROR "CLI11 target missing.")
endif()

# ----- cppzmq (system libzmq required) ----------------------------------------
find_package(cppzmq QUIET)
if(NOT TARGET cppzmq)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(ZMQ REQUIRED libzmq)
  find_path(CPPZMQ_INCLUDE zmq.hpp
    HINTS /usr/include /usr/local/include)
  if(NOT CPPZMQ_INCLUDE)
    message(FATAL_ERROR "cppzmq header (zmq.hpp) not found.")
  endif()
  add_library(cppzmq INTERFACE)
  target_include_directories(cppzmq INTERFACE ${CPPZMQ_INCLUDE})
  target_link_libraries(cppzmq INTERFACE ${ZMQ_LIBRARIES})
  target_include_directories(cppzmq INTERFACE ${ZMQ_INCLUDE_DIRS})
endif()

# ----- GoogleTest -------------------------------------------------------------
FetchContent_Declare(googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
)
FetchContent_MakeAvailable(googletest)
