PROJECT("cjet tests" C CXX)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

INCLUDE(CTest)

FIND_PACKAGE(Boost 1.46.0 REQUIRED COMPONENTS unit_test_framework)
IF(Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
  ADD_DEFINITIONS(-DBOOST_SYSTEM_NO_DEPRECATED)
ENDIF(Boost_FOUND)

ADD_CUSTOM_COMMAND(
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/config.h
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../config.h ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/config.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../config.h
)
ADD_CUSTOM_COMMAND(
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/peer_io.h
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../peer_io.h ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/peer_io.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../peer_io.h
)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../../../)

SET(CMAKE_CXX_FLAGS "-ggdb --coverage" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS "-ggdb --coverage" CACHE STRING "" FORCE)

ADD_DEFINITIONS(-DTESTING)

SET(READBUFFER_TEST
	${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/config.h
	${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/peer_io.h
	../../../cJSON.c
	../../../peer.c
	../../../response.c
	../../../state.c
	../io.c
	ReadbufferTest.cpp
)
ADD_EXECUTABLE(readbuffer_test.bin ${READBUFFER_TEST})
TARGET_LINK_LIBRARIES(
	readbuffer_test.bin
	${Boost_LIBRARIES}
)

SET(JSON_PARSE_TEST
	${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/config.h
	${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/peer_io.h
	../../../cJSON.c
	../../../fetch.c
	../../../parse.c
	../../../peer.c
	../../../response.c
	../../../state.c
	../io.c
	Parse.cpp
)
ADD_EXECUTABLE(parse_test.bin ${JSON_PARSE_TEST})
TARGET_LINK_LIBRARIES(
	parse_test.bin
	${Boost_LIBRARIES}
)

SET(STATE_TEST
	../../../cJSON.c
	../../../response.c
	../../../state.c
	../../../peer.c
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
ADD_TEST(readbuffer_test readbuffer_test.bin)
ADD_TEST(state_test state_test.bin)

