CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

SET(PROJECTNAME cjet_tests)
PROJECT(${PROJECTNAME} C CXX)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../../cmake/)
INCLUDE(version)
INCLUDE(defaults)

GENERATE_VERSION(../cjet_version)

CONFIGURE_FILE(../linux/config/os_config.h.in ${PROJECT_BINARY_DIR}/generated/os_config.h)
CONFIGURE_FILE(../cjet_config.h.in ${PROJECT_BINARY_DIR}/generated/cjet_config.h)
CONFIGURE_FILE(../version.h.in ${PROJECT_BINARY_DIR}/generated/version.h)

FIND_PACKAGE(Boost 1.46.0 REQUIRED COMPONENTS unit_test_framework filesystem)
IF(Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
  ADD_DEFINITIONS(-DBOOST_SYSTEM_NO_DEPRECATED)
ENDIF(Boost_FOUND)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../)
INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR}/)

ADD_DEFINITIONS(-D_GNU_SOURCE)

SET(WARN_SWITCHES "-Wall")

SET(CMAKE_CXX_FLAGS "-pipe ${WARN_SWITCHES} -ggdb --coverage")
SET(CMAKE_C_FLAGS "-pipe -std=c99 ${WARN_SWITCHES} -ggdb --coverage")

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables")
SET(CMAKE_CXX_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables")

IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -Og")
		SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Og")
	ELSEIF(CMAKE_C_COMPILER_ID STREQUAL GNU)
		SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -O0")
		SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -O0")
	ENDIF()
ENDIF()

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-O2,--gc-sections,-s")

ADD_DEFINITIONS(-DTESTING)
ADD_DEFINITIONS(-D_BSD_SOURCE=1 -D_DEFAULT_SOURCE=1)

INCLUDE(hardening)

FILE(COPY "../../scripts/make_coverage.sh" DESTINATION ${CMAKE_BINARY_DIR})

IF(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF()
MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "Target Processor: ${CMAKE_SYSTEM_PROCESSOR}")

add_library(jet STATIC 
	../alloc.c
	../authenticate.c
	../config.c
 	../element.c
 	../fetch.c
 	../groups.c
 	../info.c
 	../jet_string.c
 	../json/cJSON.c
 	../linux/jet_string.c
 	../parse.c
 	../peer.c
 	../posix/jet_string.c
 	../response.c
 	../router.c
 	../table.c
 	../timer.c
	../utf8_checker.c
)

SET (ZLIB_FILES
	../zlib/adler32.c
	../zlib/deflate.c
	../zlib/inffast.c
	../zlib/inflate.c
	../zlib/inftrees.c
	../zlib/trees.c
	../zlib/zutil.c
)

FOREACH(_file ${ZLIB_FILES})
        SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-DNO_GZIP")
ENDFOREACH()

add_library(zlib STATIC  ${ZLIB_FILES})

SET(CJET_TEST_INPUT_FILES
        input_data/no_json.json
        input_data/passwd_call_group_no_array.json
        input_data/passwd_fetch_group_no_array.json
        input_data/passwd_no_json_data.json
        input_data/passwd_no_user_data.json
        input_data/passwd_set_group_no_array.json
        input_data/passwd_std.json
)

FOREACH(_file ${CJET_TEST_INPUT_FILES})
        configure_file(${PROJECT_SOURCE_DIR}/${_file}  ${CMAKE_CURRENT_BINARY_DIR}/${_file}  COPYONLY)
ENDFOREACH()

SET(AUTH_FILE_TEST
	../posix/auth_file.c
	auth_file_test.cpp
	log.cpp
)
ADD_EXECUTABLE(auth_file_test.bin ${AUTH_FILE_TEST})
TARGET_LINK_LIBRARIES(
	auth_file_test.bin
	crypt
	jet
	${Boost_LIBRARIES}
)

SET(INFO_TEST
	../linux/timer_linux.c
	info_test.cpp
	log.cpp
)
ADD_EXECUTABLE(info_test.bin ${INFO_TEST})
TARGET_LINK_LIBRARIES(
	info_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(RESPONSE_TEST
	../linux/timer_linux.c
	log.cpp
	response_test.cpp
)
ADD_EXECUTABLE(response_test.bin ${RESPONSE_TEST})
TARGET_LINK_LIBRARIES(
	response_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(ROUTER_TEST
	../linux/timer_linux.c
	log.cpp
	router_test.cpp
)
ADD_EXECUTABLE(router_test.bin ${ROUTER_TEST})
TARGET_LINK_LIBRARIES(
	router_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(STRING_TEST
	../alloc.c
	../linux/jet_string.c
	log.cpp
	string_test.cpp
)
ADD_EXECUTABLE(string_test.bin ${STRING_TEST})
TARGET_LINK_LIBRARIES(
	string_test.bin
	${Boost_LIBRARIES}
)

SET(BUFFEREDSOCKET_TEST
	../alloc.c
	../buffered_socket.c
	../linux/jet_string.c
	buffered_socket_test.cpp
	log.cpp
)
ADD_EXECUTABLE(buffered_socket_test.bin ${BUFFEREDSOCKET_TEST})
TARGET_LINK_LIBRARIES(
	buffered_socket_test.bin
	${Boost_LIBRARIES}
)

SET(HTTP_CONNECTION_TEST
    ../alloc.c
    ../http-parser/http_parser.c
    ../http_connection.c
    ../http_server.c
    ../linux/jet_string.c
    log.cpp
    http_connection_test.cpp
)
ADD_EXECUTABLE(http_connection_test.bin ${HTTP_CONNECTION_TEST})
TARGET_LINK_LIBRARIES(
	http_connection_test.bin
	${Boost_LIBRARIES}
)

SET(CONFIG_TEST
	../linux/timer_linux.c
	config_test.cpp
	log.cpp
)
ADD_EXECUTABLE(config_test.bin ${CONFIG_TEST})
TARGET_LINK_LIBRARIES(
	config_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(PEER_TEST
	../linux/timer_linux.c
	log.cpp
	peer_test.cpp
)
ADD_EXECUTABLE(peer_test.bin ${PEER_TEST})
TARGET_LINK_LIBRARIES(
	peer_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(JSON_PARSE_TEST
	../linux/timer_linux.c
	auth_stub.cpp
	log.cpp
	parse_test.cpp
)
ADD_EXECUTABLE(parse_test.bin ${JSON_PARSE_TEST})
TARGET_LINK_LIBRARIES(
	parse_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(STATE_TEST
	../linux/timer_linux.c
	auth_stub.cpp
	log.cpp
	state_test.cpp
)
ADD_EXECUTABLE(state_test.bin ${STATE_TEST})
TARGET_LINK_LIBRARIES(
	state_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(METHOD_TEST
	../linux/timer_linux.c
	auth_stub.cpp
	log.cpp
	method_test.cpp
)
ADD_EXECUTABLE(method_test.bin ${METHOD_TEST})
TARGET_LINK_LIBRARIES(
	method_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(COMBINED_TEST
	../linux/timer_linux.c
	auth_stub.cpp
	log.cpp
	combined_test.cpp
)
ADD_EXECUTABLE(combined_test.bin ${COMBINED_TEST})
TARGET_LINK_LIBRARIES(
	combined_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(FETCH_TEST
	../linux/timer_linux.c
	auth_stub.cpp
	log.cpp
	fetch_test.cpp
)
ADD_EXECUTABLE(fetch_test.bin ${FETCH_TEST})
TARGET_LINK_LIBRARIES(
	fetch_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(ALLOC_TEST
	../alloc.c
	log.cpp
	alloc_test.cpp
)
ADD_EXECUTABLE(alloc_test.bin ${ALLOC_TEST})
TARGET_LINK_LIBRARIES(
	alloc_test.bin
	${Boost_LIBRARIES}
)

SET(ACCESS_TEST
	../linux/timer_linux.c
	access_test.cpp
	log.cpp
)
ADD_EXECUTABLE(access_test.bin ${ACCESS_TEST})
TARGET_LINK_LIBRARIES(
	access_test.bin
	jet
	${Boost_LIBRARIES}
)

SET(BASE64_TEST
	../base64.c
	log.cpp
	base64_test.cpp
)
ADD_EXECUTABLE(base64_test.bin ${BASE64_TEST})
TARGET_LINK_LIBRARIES(
	base64_test.bin
	${Boost_LIBRARIES}
)

SET(HTTP_PARSER_TEST
	../http-parser/http_parser.c
	../http-parser/test.c
	log.cpp
)
ADD_EXECUTABLE(http_parser_test.bin ${HTTP_PARSER_TEST})
TARGET_LINK_LIBRARIES(
	http_parser_test.bin
)

SET(WEBSOCKET_TEST
    ../base64.c
    ../compression.c
    ../buffered_socket.c
    ../http-parser/http_parser.c
    ../http_connection.c
    ../http_server.c
    ../linux/jet_endian.c
    ../linux/random.c
    ../sha1/sha1.c
    ../tests/websocket_test.cpp
    ../tests/log.cpp
    ../websocket.c
)
ADD_EXECUTABLE(websocket_test.bin ${WEBSOCKET_TEST})
TARGET_LINK_LIBRARIES(
	websocket_test.bin
	jet
	zlib
	${Boost_LIBRARIES}
)

SET(WEBSOCKET_FRAME_TEST
    ../base64.c
    ../compression.c
    ../http-parser/http_parser.c
    ../http_connection.c
    ../http_server.c
    ../linux/jet_endian.c
    ../linux/random.c
    ../sha1/sha1.c
    ../tests/websocket_frame_test.cpp
    ../tests/log.cpp
    ../websocket.c
)
ADD_EXECUTABLE(websocket_frame_test.bin ${WEBSOCKET_FRAME_TEST})
TARGET_LINK_LIBRARIES(
	websocket_frame_test.bin
	jet
	zlib
	${Boost_LIBRARIES}
)

SET(WEBSOCKET_PEER_TEST
    ../linux/timer_linux.c
    ../base64.c
    ../compression.c
    ../http-parser/http_parser.c
    ../http_connection.c
    ../http_server.c
    ../linux/jet_endian.c
    ../linux/random.c
    ../sha1/sha1.c
    ../websocket.c
    ../websocket_peer.c
    auth_stub.cpp
    log.cpp
    websocket_peer_test.cpp
)
ADD_EXECUTABLE(websocket_peer_test.bin ${WEBSOCKET_PEER_TEST})
TARGET_LINK_LIBRARIES(
    websocket_peer_test.bin
    jet
	zlib
    ${Boost_LIBRARIES}
)

SET(UTF8_CHECKER_TEST
    ../utf8_checker.c
    utf8_checker_test.cpp
)
ADD_EXECUTABLE(utf8_checker_test.bin ${UTF8_CHECKER_TEST})
TARGET_LINK_LIBRARIES(
    utf8_checker_test.bin
    ${Boost_LIBRARIES}
) 

SET(COMPRESSION_TEST
    ../base64.c
    ../compression.c
    ../http-parser/http_parser.c
    ../http_connection.c
    ../http_server.c
    ../linux/jet_endian.c
    ../linux/random.c
    ../sha1/sha1.c
    ../websocket.c
    compression_test.cpp
    log.cpp
)
ADD_EXECUTABLE(compression_test.bin ${COMPRESSION_TEST})
TARGET_LINK_LIBRARIES(
    compression_test.bin
    jet
    zlib
    ${Boost_LIBRARIES}
)
