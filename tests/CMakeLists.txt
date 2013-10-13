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
	../peer.c
)

ADD_EXECUTABLE(readbuffer_test.bin ${READBUFFER_TEST})

target_link_libraries (
	readbuffer_test.bin
	${Boost_LIBRARIES}
)

enable_testing()

add_test(readbuffer_test readbuffer_test.bin)

