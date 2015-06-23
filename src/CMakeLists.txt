CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(PROJECTNAME cjet)
PROJECT(${PROJECTNAME} C)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/)
INCLUDE(defaults)

ADD_DEFINITIONS(-D_BSD_SOURCE=1 -D_DEFAULT_SOURCE=1)

CONFIGURE_FILE(linux/epoll/config/config.h.in ${PROJECT_BINARY_DIR}/config/config.h)
CONFIGURE_FILE(version.h.in ${PROJECT_BINARY_DIR}/version.h)

ADD_CUSTOM_TARGET(REVISION_GEN
	${CMAKE_COMMAND} -P ${PROJECT_SOURCE_DIR}/../cmake/version.cmake
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

SET(WARN_SWITCHES "-Wall -Werror -Wshadow -Wextra -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wpointer-arith -Wformat=2 -Wwrite-strings -Wmissing-prototypes -pedantic")

SET(CMAKE_C_FLAGS "-pipe -fvisibility=hidden -fno-common -std=c99 ${WARN_SWITCHES}")
IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
	ENDIF()
ENDIF()

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables -fomit-frame-pointer")

IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -Og -ggdb")
	ELSEIF(CMAKE_C_COMPILER_ID STREQUAL GNU)
		SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -O0 -ggdb")
	ENDIF()
ENDIF()

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--hash-style=gnu -Wl,--as-needed")
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-O2 -Wl,--gc-sections")
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl,-O0")

IF(NOT CMAKE_BUILD_TYPE )
	SET(CMAKE_BUILD_TYPE RELEASE)
ENDIF()

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/linux/epoll/)
INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR}/)

SET(CJET_FILES
	linux/epoll/io.c
	linux/epoll/io_loop.c
	linux/epoll/timer.c
	linux/main.c
	config.c
	jet_string.c
	json/cJSON.c
	fetch.c
	info.c
	method.c
	parse.c
	peer.c
	response.c
	router.c
	state.c
	uuid.c
)
SET_SOURCE_FILES_PROPERTIES(linux/epoll/timer.c PROPERTIES COMPILE_FLAGS -std=c89)
ADD_EXECUTABLE(cjet.bin
	${CJET_FILES}
)
ADD_DEPENDENCIES(cjet.bin REVISION_GEN)
TARGET_LINK_LIBRARIES(
	cjet.bin
	m
)

