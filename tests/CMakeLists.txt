project("cjet tests" C CXX)

cmake_minimum_required(VERSION 2.8)

set (Boost_NO_SYSTEM_PATHS ON)
add_definitions(-DBOOST_SYSTEM_NO_DEPRECATED)
set(BOOST_ROOT "/opt/boost/1.55.0" CACHE PATH "")

find_package(Boost 1.55 COMPONENTS unit_test_framework)
IF(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
endif(Boost_FOUND)

add_definitions(-DTESTING)

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

target_link_libraries (
	parse_test.bin
	${Boost_LIBRARIES}
)

target_link_libraries (
	readbuffer_test.bin
	${Boost_LIBRARIES}
)

target_link_libraries (
	state_test.bin
	${Boost_LIBRARIES}
)

enable_testing()

add_test(parse_test parse_test.bin)
add_test(readbuffer_test readbuffer_test.bin)
add_test(state_test state_test.bin)

