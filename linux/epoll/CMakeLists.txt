PROJECT("cjet" C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

FUNCTION(GLIBC_DETECT _VERSION)

SET(_GLIB_SOURCE_DETECT "
#include <limits.h>
#include <stdio.h>
int main()
{
  printf(\"%d%d\",__GLIBC__, __GLIBC_MINOR__);
  return 0;
}
")

FILE(WRITE /tmp/build/cmake/glibc.c "${_GLIB_SOURCE_DETECT}\n")

TRY_RUN(POST26_GLIBC_DETECTED
		POST26_GLIBC_COMPILE
        /tmp/build/cmake
		/tmp/build/cmake/glibc.c
        RUN_OUTPUT_VARIABLE GLIBC_VERSION)

IF(GLIBC_VERSION AND POST26_GLIBC_COMPILE)
	MESSAGE(STATUS "GLIBC_VERSION=${GLIBC_VERSION}")
	SET(${_VERSION} ${GLIBC_VERSION} PARENT_SCOPE)
else()
	MESSAGE(STATUS "NOTE: Could not detect GLIBC_VERSION from compiler")
endif()

ENDFUNCTION(GLIBC_DETECT)

SET(GLIBC_VERSION)
GLIBC_DETECT(GLIBC_VERSION)

IF(GLIBC_VERSION GREATER 219)
	add_definitions(-D_DEFAULT_SOURCE=1)
ELSE()
	add_definitions(-D_BSD_SOURCE=1)
ENDIF()


SET(WARN_SWITCHES "-pipe -Wall -Werror -Wshadow -Wextra -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wpointer-arith -Wformat=2 -Wwrite-strings -Wmissing-prototypes -pedantic")

SET(CMAKE_C_FLAGS "${WARN_SWITCHES} -fvisibility=hidden -fno-common -std=c99" CACHE STRING "" FORCE)
IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto" CACHE STRING "" FORCE)
	ENDIF()
ELSEIF(CMAKE_C_COMPILER_ID STREQUAL Clang)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function" CACHE STRING "" FORCE)
#	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 3.5.0)
#		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto" CACHE STRING "" FORCE)
#	ENDIF()
ENDIF()

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables -fomit-frame-pointer" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb" CACHE STRING "" FORCE)

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--hash-style=gnu -Wl,--as-needed" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-O2 -Wl,--gc-sections" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl,-O0" CACHE STRING "" FORCE)

IF(NOT CMAKE_BUILD_TYPE )
	SET(CMAKE_BUILD_TYPE RELEASE CACHE STRING "" FORCE)
ENDIF()

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../../)

SET(DYNLIBS
	-lm
)

SET(CJET_FILES
	io.c
	io_loop.c
	../main.c
	../../json/cJSON.c
	../../fetch.c
	../../parse.c
	../../peer.c
	../../response.c
	../../router.c
	../../state.c
	../../uuid.c
)
ADD_EXECUTABLE(cjet.bin
	${CJET_FILES}
)
TARGET_LINK_LIBRARIES(
	cjet.bin
	${DYNLIBS}
)

SET(ECHO_FILES
	io.c
	io_loop.c
	../main.c
	../../json/cJSON.c
	../../echo.c
	../../fetch.c
	../../peer.c
	../../response.c
	../../router.c
	../../state.c
	../../uuid.c
)
ADD_EXECUTABLE(echo.bin
	${ECHO_FILES}
)
TARGET_LINK_LIBRARIES(
	echo.bin
	${DYNLIBS}
)

