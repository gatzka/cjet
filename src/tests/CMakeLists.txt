PROJECT("cjet tests" C CXX)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../../)
INCLUDE(defaults)

CONFIGURE_FILE(../linux/epoll/config/config.h.in ${PROJECT_BINARY_DIR}/config/config.h)

FIND_PACKAGE(Boost 1.46.0 REQUIRED COMPONENTS unit_test_framework)
IF(Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  LIST(APPEND ADDITIONAL_LIBS ${Boost_LIBRARIES})
  ADD_DEFINITIONS(-DBOOST_SYSTEM_NO_DEPRECATED)
ENDIF(Boost_FOUND)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../linux/epoll/)
INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR}/)

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

file(COPY "../../scripts/make_coverage.sh" DESTINATION ${CMAKE_BINARY_DIR})

SET(RESPONSE_TEST
	../json/cJSON.c
	../response.c
	response_test.cpp
)
ADD_EXECUTABLE(response_test.bin ${RESPONSE_TEST})
TARGET_LINK_LIBRARIES(
	response_test.bin
	${Boost_LIBRARIES}
)

SET(PEER_TEST
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
	../json/cJSON.c
	../config.c
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
	../response.c
	../router.c
	../state.c
	../peer.c
	../uuid.c
	log.cpp
	state_test.cpp
)
ADD_EXECUTABLE(state_test.bin ${STATE_TEST})
TARGET_LINK_LIBRARIES(
	state_test.bin
	${Boost_LIBRARIES}
)

SET(COMBINED_TEST
	../fetch.c
	../json/cJSON.c
	../response.c
	../router.c
	../state.c
	../peer.c
	../uuid.c
	log.cpp
	combined_test.cpp
)
ADD_EXECUTABLE(combined_test.bin ${COMBINED_TEST})
TARGET_LINK_LIBRARIES(
	combined_test.bin
	${Boost_LIBRARIES}
)
