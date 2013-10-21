project("cjet tests" C CXX)

cmake_minimum_required(VERSION 2.8)

find_package(Boost 1.52 COMPONENTS unit_test_framework)
IF(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
endif(Boost_FOUND)

add_definitions(-DTESTING)


SET(READBUFFER_TEST
	ReadbufferTest.cpp
	../cJSON.c
	../peer.c
	../state.c
)

SET(JSON_PARSE_TEST
	Parse.cpp
	../parse.c
	../peer.c
	../response.c
	../state.c
	../cJSON.c
)

ADD_EXECUTABLE(parse_test.bin ${JSON_PARSE_TEST})
ADD_EXECUTABLE(readbuffer_test.bin ${READBUFFER_TEST})

target_link_libraries (
	parse_test.bin
	${Boost_LIBRARIES}
)

target_link_libraries (
	readbuffer_test.bin
	${Boost_LIBRARIES}
)

enable_testing()

add_test(parse_test parse_test.bin)
add_test(readbuffer_test readbuffer_test.bin)

