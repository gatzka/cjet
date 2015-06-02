PROJECT("cjet binary" C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../)
INCLUDE(defaults)

ADD_DEFINITIONS(-D_BSD_SOURCE=1 -D_DEFAULT_SOURCE=1)

CONFIGURE_FILE(linux/epoll/config/config.h.in ${PROJECT_BINARY_DIR}/config/config.h)

SET(WARN_SWITCHES "-Wall -Werror -Wshadow -Wextra -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wpointer-arith -Wformat=2 -Wwrite-strings -Wmissing-prototypes -pedantic")

SET(CMAKE_C_FLAGS "-pipe ${WARN_SWITCHES} -fvisibility=hidden -fno-common -std=c99" CACHE STRING "" FORCE)
IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto" CACHE STRING "" FORCE)
	ENDIF()
ENDIF()

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables -fomit-frame-pointer" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb" CACHE STRING "" FORCE)

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--hash-style=gnu -Wl,--as-needed" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-O2 -Wl,--gc-sections" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl,-O0" CACHE STRING "" FORCE)

IF(NOT CMAKE_BUILD_TYPE )
	SET(CMAKE_BUILD_TYPE RELEASE CACHE STRING "" FORCE)
ENDIF()

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/linux/epoll/)
INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR}/)

SET(CJET_FILES
	linux/epoll/io.c
	linux/epoll/io_loop.c
	linux/main.c
	config.c
	jet_string.c
	json/cJSON.c
	fetch.c
	method.c
	parse.c
	peer.c
	response.c
	router.c
	state.c
	uuid.c
)
ADD_EXECUTABLE(cjet.bin
	${CJET_FILES}
)
TARGET_LINK_LIBRARIES(
	cjet.bin
	m
)

