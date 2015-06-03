PROJECT("cjet" C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

ADD_SUBDIRECTORY(src/) 
ADD_SUBDIRECTORY(src/tests/) 
ADD_SUBDIRECTORY(src/linux/epoll/tests/) 

ENABLE_TESTING()
SET(CTEST_MEMORYCHECK_COMMAND "valgrind")
SET(CTEST_MEMORYCHECK_COMMAND_OPTIONS "--tool=memcheck -v")

ADD_TEST(NAME parse_test COMMAND parse_test.bin)
ADD_TEST(NAME peer_test COMMAND peer_test.bin)
ADD_TEST(NAME readbuffer_test COMMAND readbuffer_test.bin)
ADD_TEST(NAME response_test COMMAND response_test.bin)
ADD_TEST(NAME state_test COMMAND state_test.bin)
ADD_TEST(NAME combined_test COMMAND combined_test.bin)
ADD_TEST(NAME fetch_test COMMAND combined_test.bin)
