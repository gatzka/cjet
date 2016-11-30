PROJECT("cjet binary and tests" C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

option(FEATURE_POST_BUILD_UNITTEST  "Automatically run unit-tests as a post build step" ON)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

OPTION(COVERALLS "Generate coveralls data" OFF)

IF(COVERALLS)
    INCLUDE(Coveralls)
ENDIF()

IF(COVERALLS)
    SET(COVERAGE_SRCS
		${PROJECT_SOURCE_DIR}/src/base64.c
		# ${PROJECT_SOURCE_DIR}/src/base64.h
		# ${PROJECT_SOURCE_DIR}/src/buffered_reader.h
		${PROJECT_SOURCE_DIR}/src/buffered_socket.c
		# ${PROJECT_SOURCE_DIR}/src/buffered_socket.h
		# ${PROJECT_SOURCE_DIR}/src/compiler.h
		${PROJECT_SOURCE_DIR}/src/config.c
		# ${PROJECT_SOURCE_DIR}/src/config.h
		# ${PROJECT_SOURCE_DIR}/src/eventloop.h
		${PROJECT_SOURCE_DIR}/src/fetch.c
		# ${PROJECT_SOURCE_DIR}/src/fetch.h
		# ${PROJECT_SOURCE_DIR}/src/hashtable.h
		${PROJECT_SOURCE_DIR}/src/http_connection.c
		# ${PROJECT_SOURCE_DIR}/src/http_connection.h
		${PROJECT_SOURCE_DIR}/src/http_server.c
		# ${PROJECT_SOURCE_DIR}/src/http_server.h
		${PROJECT_SOURCE_DIR}/src/info.c
		# ${PROJECT_SOURCE_DIR}/src/info.h
		# ${PROJECT_SOURCE_DIR}/src/jet_endian.h
		# ${PROJECT_SOURCE_DIR}/src/jet_server.h
		# ${PROJECT_SOURCE_DIR}/src/jet_string.h
		# ${PROJECT_SOURCE_DIR}/src/linux/alloc.c
		# ${PROJECT_SOURCE_DIR}/src/linux/buffered_socket_alloc.c
		# ${PROJECT_SOURCE_DIR}/src/linux/cmdline_config.h
		# ${PROJECT_SOURCE_DIR}/src/linux/eventloop_epoll.c
		# ${PROJECT_SOURCE_DIR}/src/linux/eventloop_epoll.h
		# ${PROJECT_SOURCE_DIR}/src/linux/jet_endian.c
		# ${PROJECT_SOURCE_DIR}/src/linux/jet_string.c
		# ${PROJECT_SOURCE_DIR}/src/linux/linux_io.c
		# ${PROJECT_SOURCE_DIR}/src/linux/linux_io.h
		# ${PROJECT_SOURCE_DIR}/src/linux/main.c
		# ${PROJECT_SOURCE_DIR}/src/linux/socket.c
		# ${PROJECT_SOURCE_DIR}/src/linux/timer_linux.c
		# ${PROJECT_SOURCE_DIR}/src/linux/uuid.c
		# ${PROJECT_SOURCE_DIR}/src/linux/websocket_random.c
		# ${PROJECT_SOURCE_DIR}/src/list.h
		# ${PROJECT_SOURCE_DIR}/src/log.h
		${PROJECT_SOURCE_DIR}/src/parse.c
		# ${PROJECT_SOURCE_DIR}/src/parse.h
		${PROJECT_SOURCE_DIR}/src/peer.c
		# b${PROJECT_SOURCE_DIR}/src/peer.h
		${PROJECT_SOURCE_DIR}/src/response.c
		# ${PROJECT_SOURCE_DIR}/src/response.h
		${PROJECT_SOURCE_DIR}/src/router.c
		# ${PROJECT_SOURCE_DIR}/src/router.h
		# ${PROJECT_SOURCE_DIR}/src/sha1/sha1.h
		${PROJECT_SOURCE_DIR}/src/sha1/sha1.c
		${PROJECT_SOURCE_DIR}/src/socket.h
		${PROJECT_SOURCE_DIR}/src/socket_peer.c
		# ${PROJECT_SOURCE_DIR}/src/socket_peer.h
		# ${PROJECT_SOURCE_DIR}/src/state.h
		${PROJECT_SOURCE_DIR}/src/table.c
		# ${PROJECT_SOURCE_DIR}/src/table.h
		# ${PROJECT_SOURCE_DIR}/src/timer.h
		# ${PROJECT_SOURCE_DIR}/src/url_handler.h
		# ${PROJECT_SOURCE_DIR}/src/util.h
		# ${PROJECT_SOURCE_DIR}/src/uuid.h
		${PROJECT_SOURCE_DIR}/src/websocket.c
		# ${PROJECT_SOURCE_DIR}/src/websocket.h
		${PROJECT_SOURCE_DIR}/src/websocket_peer.c
		# ${PROJECT_SOURCE_DIR}/src/websocket_peer.h
		)

    # Create the coveralls target.
    coveralls_setup(
        "${COVERAGE_SRCS}" # The source files.
        ON                 # If we should upload.
        ) # (Optional) Alternate project cmake module path.
        #"${PROJECT_SOURCE_DIR}/CMakeModules/") # (Optional) Alternate project cmake module path.
ENDIF()

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
  ADD_TEST(NAME websocket_frame_test COMMAND websocket_frame_test.bin)
  ADD_TEST(NAME websocket_test COMMAND websocket_test.bin)
  ADD_TEST(NAME websocket_peer_test COMMAND websocket_peer_test.bin)

endif()
