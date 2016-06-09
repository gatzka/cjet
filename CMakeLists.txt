PROJECT("cjet binary and tests" C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

option(FEATURE_POST_BUILD_UNITTEST  "Automatically run unit-tests as a post build step" ON)


ADD_SUBDIRECTORY(src/)

if(FEATURE_POST_BUILD_UNITTEST)
  ## run tests after build.
  ADD_SUBDIRECTORY(src/tests/)
  ENABLE_TESTING()

  SET(CTEST_MEMORYCHECK_COMMAND "valgrind")
  SET(CTEST_MEMORYCHECK_COMMAND_OPTIONS "--tool=memcheck -v")

  ADD_TEST(NAME base64_test COMMAND base64_test.bin)
  ADD_TEST(NAME buffered_socket_test COMMAND buffered_socket_test.bin)
  ADD_TEST(NAME combined_test COMMAND combined_test.bin)
  ADD_TEST(NAME config_test COMMAND config_test.bin)
  ADD_TEST(NAME fetch_test COMMAND fetch_test.bin)
  ADD_TEST(NAME http_parser_test COMMAND http_parser_test.bin)
  ADD_TEST(NAME http_connection_test COMMAND http_connection_test.bin)
  ADD_TEST(NAME info_test COMMAND info_test.bin)
  ADD_TEST(NAME method_test COMMAND method_test.bin)
  ADD_TEST(NAME parse_test COMMAND parse_test.bin)
  ADD_TEST(NAME peer_test COMMAND peer_test.bin)
  ADD_TEST(NAME response_test COMMAND response_test.bin)
  ADD_TEST(NAME router_test COMMAND router_test.bin)
  ADD_TEST(NAME state_test COMMAND state_test.bin)
  ADD_TEST(NAME string_test COMMAND string_test.bin)

endif()
