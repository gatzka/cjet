PROJECT("cjet tests" C CXX)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

INCLUDE(CTest)

FIND_PACKAGE(Boost 1.46.0 REQUIRED COMPONENTS unit_test_framework)
IF(Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
  ADD_DEFINITIONS(-DBOOST_SYSTEM_NO_DEPRECATED)
ENDIF(Boost_FOUND)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../../../)

SET(WARN_SWITCHES "-Wall -Werror")

SET(CMAKE_CXX_FLAGS "-pipe ${WARN_SWITCHES} -ggdb --coverage" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS "-pipe -std=c99 ${WARN_SWITCHES} -ggdb --coverage" CACHE STRING "" FORCE)

IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Og" CACHE STRING "" FORCE)
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Og" CACHE STRING "" FORCE)
	ELSEIF(CMAKE_C_COMPILER_ID STREQUAL GNU)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0" CACHE STRING "" FORCE)
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0" CACHE STRING "" FORCE)
	ENDIF()
ENDIF()

ADD_DEFINITIONS(-DTESTING)
ADD_DEFINITIONS(-D_BSD_SOURCE=1 -D_DEFAULT_SOURCE=1)

file(COPY "make_coverage.sh" DESTINATION ${CMAKE_BINARY_DIR})

SET(RESPONSE_TEST
	../../../json/cJSON.c
	../../../response.c
	Response.cpp
)
ADD_EXECUTABLE(response_test.bin ${RESPONSE_TEST})
TARGET_LINK_LIBRARIES(
	response_test.bin
	${Boost_LIBRARIES}
)

SET(PEER_TEST
	../../../json/cJSON.c
	../../../peer.c
	Peer.cpp
)
ADD_EXECUTABLE(peer_test.bin ${PEER_TEST})
TARGET_LINK_LIBRARIES(
	peer_test.bin
	${Boost_LIBRARIES}
)

SET(READBUFFER_TEST
	../../../json/cJSON.c
	../../../fetch.c
	../../../method.c
	../../../peer.c
	../../../response.c
	../../../router.c
	../../../state.c
	../../../uuid.c
	../io.c
	ReadbufferTest.cpp
)
ADD_EXECUTABLE(readbuffer_test.bin ${READBUFFER_TEST})
TARGET_LINK_LIBRARIES(
	readbuffer_test.bin
	${Boost_LIBRARIES}
)

SET(JSON_PARSE_TEST
	../../../json/cJSON.c
	../../../fetch.c
	../../../method.c
	../../../parse.c
	../../../peer.c
	../../../response.c
	../../../router.c
	../../../state.c
	../../../uuid.c
	Parse.cpp
)
ADD_EXECUTABLE(parse_test.bin ${JSON_PARSE_TEST})
TARGET_LINK_LIBRARIES(
	parse_test.bin
	${Boost_LIBRARIES}
)

SET(STATE_TEST
	../../../json/cJSON.c
	../../../response.c
	../../../router.c
	../../../state.c
	../../../peer.c
	../../../uuid.c
	State.cpp
)
ADD_EXECUTABLE(state_test.bin ${STATE_TEST})
TARGET_LINK_LIBRARIES(
	state_test.bin
	${Boost_LIBRARIES}
)
 
ENABLE_TESTING()
SET(CTEST_MEMORYCHECK_COMMAND "valgrind")
SET(CTEST_MEMORYCHECK_COMMAND_OPTIONS "--tool=memcheck -v")

ADD_TEST(parse_test parse_test.bin)
ADD_TEST(peer_test peer_test.bin)
ADD_TEST(readbuffer_test readbuffer_test.bin)
ADD_TEST(response_test response_test.bin)
ADD_TEST(state_test state_test.bin)

