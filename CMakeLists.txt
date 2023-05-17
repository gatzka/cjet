PROJECT("cjet binary and tests" C)

CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

option(FEATURE_POST_BUILD_UNITTEST  "Automatically run unit-tests as a post build step" ON)


# -If using fetchcontent, headers of cjson are located in the same directory as the implementation. This is why we us '#include "cJSON.h"'
# -If find_package succeeds, headers are located in '${CJSON_INCLUDE_DIRS}/cjson". 
#  In order to make '#include "cJSON.h"' work we have to add this include path

set(cJSON_REQUIREDVERSION "1.7.13")
find_package(cJSON ${cJSON_REQUIREDVERSION} QUIET)
if(cJSON_FOUND)
  # warning of strange spelling :"cJSON" for most variables but "CJSON_INCLUDE_DIRS" with capital 'C'!
  message(STATUS "Found cJSON: ${cJSON_VERSION} ${cJSON_CONFIG} ")
  include_directories("${CJSON_INCLUDE_DIRS}/cjson")
else()
  include(FetchContent)
  set(cJSON_WITH_POST_BUILD_UNITTEST OFF)
  set(cJSON_WITH_TESTS OFF)
  FetchContent_Declare(
    cJSON
    set(CJSON_BUILD_SHARED_LIBS OFF)
    set(ENABLE_CJSON_TEST OFF)
    URL https://github.com/DaveGamble/cJSON/archive/v${cJSON_REQUIREDVERSION}.zip
  )
  FetchContent_GetProperties(cJSON)
  if(NOT cJSON_POPULATED)
    message(STATUS "Fetching cJSON ${cJSON_REQUIREDVERSION}...")
    FetchContent_Populate(cJSON)
    add_subdirectory(${cJSON_SOURCE_DIR} ${cJSON_BINARY_DIR})
  endif()
  include_directories("${cJSON_SOURCE_DIR}")
endif()

ADD_SUBDIRECTORY(src/)

if(FEATURE_POST_BUILD_UNITTEST)
  ## run tests after build.
  ADD_SUBDIRECTORY(src/tests/)
  ENABLE_TESTING()

  SET(CTEST_MEMORYCHECK_COMMAND "valgrind")
  SET(CTEST_MEMORYCHECK_COMMAND_OPTIONS "--tool=memcheck -v")

  ADD_TEST(NAME access_test COMMAND access_test.bin)
  ADD_TEST(NAME alloc_test COMMAND alloc_test.bin)
  ADD_TEST(NAME auth_file_test WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src/tests COMMAND auth_file_test.bin)
  ADD_TEST(NAME base64_test COMMAND base64_test.bin)
  ADD_TEST(NAME buffered_socket_test COMMAND buffered_socket_test.bin)
  ADD_TEST(NAME combined_test COMMAND combined_test.bin)
  ADD_TEST(NAME compression_test COMMAND compression_test.bin)
  ADD_TEST(NAME config_test COMMAND config_test.bin)
  ADD_TEST(NAME fetch_test COMMAND fetch_test.bin)
  ADD_TEST(NAME http_connection_test COMMAND http_connection_test.bin)
  ADD_TEST(NAME http_parser_test COMMAND http_parser_test.bin)
  ADD_TEST(NAME info_test COMMAND info_test.bin)
  ADD_TEST(NAME method_test COMMAND method_test.bin)
  ADD_TEST(NAME parse_test COMMAND parse_test.bin)
  ADD_TEST(NAME peer_test COMMAND peer_test.bin)
  ADD_TEST(NAME response_test COMMAND response_test.bin)
  ADD_TEST(NAME router_test COMMAND router_test.bin)
  ADD_TEST(NAME state_test COMMAND state_test.bin)
  ADD_TEST(NAME string_test COMMAND string_test.bin)
  ADD_TEST(NAME utf8_checker_test COMMAND utf8_checker_test.bin)
  ADD_TEST(NAME websocket_frame_test COMMAND websocket_frame_test.bin)
  ADD_TEST(NAME websocket_peer_test COMMAND websocket_peer_test.bin)
  ADD_TEST(NAME websocket_test COMMAND websocket_test.bin)

endif()
