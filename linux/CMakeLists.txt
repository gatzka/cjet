PROJECT("cjet" C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(WARN_SWITCHES "-pipe -Wall -Wshadow -Wextra -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wpointer-arith -Wformat=2 -Wwrite-strings -Wmissing-prototypes -pedantic")

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fomit-frame-pointer -flto=16 -fuse-linker-plugin" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb" CACHE STRING "" FORCE)

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--hash-style=gnu -Wl,--as-needed" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-O2 -Wl,--gc-sections" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl,-O0" CACHE STRING "" FORCE)

IF(NOT CMAKE_BUILD_TYPE )
  SET(CMAKE_BUILD_TYPE RELEASE CACHE STRING "" FORCE)
ENDIF()

FILE(COPY
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/config/)

SET(CMAKE_C_FLAGS "${WARN_SWITCHES} -std=c99" CACHE STRING "" FORCE)

ADD_LIBRARY(linux_io STATIC
	io_epoll.c
	io_mt.c
	main.c
	peer.c
)

SET(CJET_FILES
	../cJSON.c
	../lmatch.c
	../parse.c
	../response.c
	../state.c
)

SET(ECHO_FILES
	../cJSON.c
	../echo.c
	../response.c
	../state.c
)

SET(GEN_MESSAGE_HASHES
	../gen_message_hashes/main.c
)

SET(DYNLIBS
	-lm
)

ADD_EXECUTABLE(cjet.bin ${CJET_FILES})
ADD_EXECUTABLE(echo.bin ${ECHO_FILES})
ADD_EXECUTABLE(gen_message_hashes.bin ${GEN_MESSAGE_HASHES})

TARGET_LINK_LIBRARIES(
	cjet.bin
	linux_io
	${DYNLIBS}
	-pthread
)

TARGET_LINK_LIBRARIES(
	echo.bin
	linux_io
	${DYNLIBS}
	-pthread
)

