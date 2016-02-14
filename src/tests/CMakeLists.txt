CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(PROJECTNAME cjet_tests)
PROJECT(${PROJECTNAME} C CXX)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../../cmake/)
INCLUDE(version)
INCLUDE(defaults)

GENERATE_VERSION(../version.h.in)

CONFIGURE_FILE(../linux/config/os_config.h.in ${PROJECT_BINARY_DIR}/generated/os_config.h)
CONFIGURE_FILE(../cjet_config.h.in ${PROJECT_BINARY_DIR}/generated/cjet_config.h)
CONFIGURE_FILE(../version.h.in ${PROJECT_BINARY_DIR}/generated/version.h)

FIND_PACKAGE(Boost 1.46.0 REQUIRED COMPONENTS unit_test_framework)
IF(Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
  ADD_DEFINITIONS(-DBOOST_SYSTEM_NO_DEPRECATED)
ENDIF(Boost_FOUND)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../)
INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR}/)

ADD_DEFINITIONS(-D_GNU_SOURCE)

SET(WARN_SWITCHES "-Wall -Werror")

SET(CMAKE_CXX_FLAGS "-pipe ${WARN_SWITCHES} -ggdb --coverage")
SET(CMAKE_C_FLAGS "-pipe -std=c99 ${WARN_SWITCHES} -ggdb --coverage")

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables")
SET(CMAKE_CXX_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables")
IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -flto")
		SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")
	ENDIF()
ENDIF()

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

SET(INFO_TEST
	../info.c
	../json/cJSON.c
	../response.c
	info_test.cpp
	log.cpp
)
ADD_EXECUTABLE(info_test.bin ${INFO_TEST})
TARGET_LINK_LIBRARIES(
	info_test.bin
	${Boost_LIBRARIES}
)

SET(RESPONSE_TEST
	../linux/jet_string.c
	../json/cJSON.c
	../response.c
	response_test.cpp
)
ADD_EXECUTABLE(response_test.bin ${RESPONSE_TEST})
TARGET_LINK_LIBRARIES(
	response_test.bin
	${Boost_LIBRARIES}
)

SET(ROUTER_TEST
	../linux/jet_string.c
	../json/cJSON.c
	../peer.c
	../response.c
	../router.c
	log.cpp
	router_test.cpp
)
ADD_EXECUTABLE(router_test.bin ${ROUTER_TEST})
TARGET_LINK_LIBRARIES(
	router_test.bin
	${Boost_LIBRARIES}
)

SET(STRING_TEST
	../linux/jet_string.c
	string_test.cpp
)
ADD_EXECUTABLE(string_test.bin ${STRING_TEST})
TARGET_LINK_LIBRARIES(
	string_test.bin
	${Boost_LIBRARIES}
)

SET(CONFIG_TEST
	../linux/jet_string.c
	../json/cJSON.c
	../config.c
	../peer.c
	../response.c
	config_test.cpp
	log.cpp
)
ADD_EXECUTABLE(config_test.bin ${CONFIG_TEST})
TARGET_LINK_LIBRARIES(
	config_test.bin
	${Boost_LIBRARIES}
)

SET(PEER_TEST
	../linux/jet_string.c
	../json/cJSON.c
	../peer.c
	log.cpp
	peer_test.cpp
)
ADD_EXECUTABLE(peer_test.bin ${PEER_TEST})
TARGET_LINK_LIBRARIES(
	peer_test.bin
	${Boost_LIBRARIES}
)

SET(JSON_PARSE_TEST
	../config.c
	../info.c
	../linux/jet_string.c
	../json/cJSON.c
	../parse.c
	../response.c
	parse_test.cpp
)
ADD_EXECUTABLE(parse_test.bin ${JSON_PARSE_TEST})
TARGET_LINK_LIBRARIES(
	parse_test.bin
	${Boost_LIBRARIES}
)

SET(STATE_TEST
	../json/cJSON.c
	../linux/jet_string.c
	../peer.c
	../response.c
	../router.c
	../state.c
	../table.c
	../uuid.c
	log.cpp
	state_test.cpp
)
ADD_EXECUTABLE(state_test.bin ${STATE_TEST})
TARGET_LINK_LIBRARIES(
	state_test.bin
	${Boost_LIBRARIES}
)

SET(METHOD_TEST
	../fetch.c
	../json/cJSON.c
	../linux/jet_string.c
	../peer.c
	../response.c
	../router.c
	../state.c
	../table.c
	../uuid.c
	log.cpp
	method_test.cpp
)
ADD_EXECUTABLE(method_test.bin ${METHOD_TEST})
TARGET_LINK_LIBRARIES(
	method_test.bin
	${Boost_LIBRARIES}
)

SET(COMBINED_TEST
	../fetch.c
	../json/cJSON.c
	../linux/jet_string.c
	../peer.c
	../response.c
	../router.c
	../state.c
	../table.c
	../uuid.c
	log.cpp
	combined_test.cpp
)
ADD_EXECUTABLE(combined_test.bin ${COMBINED_TEST})
TARGET_LINK_LIBRARIES(
	combined_test.bin
	${Boost_LIBRARIES}
)

SET(FETCH_TEST
	../fetch.c
	../json/cJSON.c
	../linux/jet_string.c
	../peer.c
	../response.c
	../router.c
	../state.c
	../table.c
	../uuid.c
	log.cpp
	fetch_test.cpp
)
ADD_EXECUTABLE(fetch_test.bin ${FETCH_TEST})
TARGET_LINK_LIBRARIES(
	fetch_test.bin
	${Boost_LIBRARIES}
)
