PROJECT("cjet tests" C CXX)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

FIND_PACKAGE(Boost COMPONENTS unit_test_framework)
IF(Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
  ADD_DEFINITIONS(-DBOOST_SYSTEM_NO_DEPRECATED)
ENDIF(Boost_FOUND)

ADD_DEFINITIONS(-DTESTING)

SET(READBUFFER_TEST
	ReadbufferTest.cpp
	../cJSON.c
	../peer.c
	../response.c
	../state.c
)

SET(JSON_PARSE_TEST
	Parse.cpp
	../cJSON.c
	../parse.c
	../peer.c
	../response.c
	../state.c
)

SET(STATE_TEST
	State.cpp
	../cJSON.c
	../peer.c
	../response.c
	../state.c
)

ADD_EXECUTABLE(parse_test.bin ${JSON_PARSE_TEST})
ADD_EXECUTABLE(readbuffer_test.bin ${READBUFFER_TEST})
ADD_EXECUTABLE(state_test.bin ${STATE_TEST})

TARGET_LINK_LIBRARIES(
	parse_test.bin
	${Boost_LIBRARIES}
)

TARGET_LINK_LIBRARIES(
	readbuffer_test.bin
	${Boost_LIBRARIES}
)

TARGET_LINK_LIBRARIES(
	state_test.bin
	${Boost_LIBRARIES}
)

ENABLE_TESTING()

ADD_TEST(parse_test parse_test.bin)
ADD_TEST(readbuffer_test readbuffer_test.bin)
ADD_TEST(state_test state_test.bin)

