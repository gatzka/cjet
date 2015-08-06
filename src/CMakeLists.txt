CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(PROJECTNAME cjet)
PROJECT(${PROJECTNAME} C)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/)
INCLUDE(defaults)

CONFIGURE_FILE(linux/config/os_config.h.in ${PROJECT_BINARY_DIR}/config/os_config.h)
CONFIGURE_FILE(cjet_config.h.in ${PROJECT_BINARY_DIR}/config/cjet_config.h)
CONFIGURE_FILE(version.h.in ${PROJECT_BINARY_DIR}/version.h)

ADD_CUSTOM_TARGET(REVISION_GEN
	${CMAKE_COMMAND} -P ${PROJECT_SOURCE_DIR}/../cmake/version.cmake
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

SET(WARN_SWITCHES "-Wall -Werror -Wshadow -Wextra -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wpointer-arith -Wformat=2 -Wwrite-strings -Wmissing-prototypes -pedantic")

SET(CMAKE_C_FLAGS "-pipe -fvisibility=hidden -fno-common ${WARN_SWITCHES}")

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables -fomit-frame-pointer")
IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -flto")
	ENDIF()
ENDIF()

IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
	IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8.0)
		SET(CMAKE_C_FLAGS_DEBUG "-Og -ggdb")
	ELSEIF(CMAKE_C_COMPILER_ID STREQUAL GNU)
		SET(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
	ENDIF()
ENDIF()

IF(CMAKE_C_COMPILER_ID STREQUAL GNU AND CMAKE_C_COMPILER_VERSION VERSION_GREATER 5.0.0)
	SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fsanitize=undefined")
ENDIF()

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--hash-style=gnu,--as-needed")
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-O2,--gc-sections,-s")
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl,-O0")

IF(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF()

MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "Target Processor: ${CMAKE_SYSTEM_PROCESSOR}")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/linux/)
INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR}/)

INCLUDE(hardening)

SET(CJET_FILES
	config.c
	fetch.c
	info.c
	json/cJSON.c
	method.c
	parse.c
	peer.c
	response.c
	router.c
	state.c
	uuid.c
)

SET(CJET_LINUX_FILES
	linux/io.c
	linux/io_loop.c
	linux/timer.c
	linux/jet_string.c
	linux/main.c
)

FOREACH(_file ${CJET_FILES})
	FILE(SHA512 ${PROJECT_SOURCE_DIR}/${_file} checksum)
    SET_SOURCE_FILES_PROPERTIES(${_file} PROPERTIES COMPILE_FLAGS " -frandom-seed=${checksum} -std=c99")
ENDFOREACH()

FOREACH(_file ${CJET_LINUX_FILES})
	FILE(SHA512 ${PROJECT_SOURCE_DIR}/${_file} checksum)
	SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=${checksum} -D_GNU_SOURCE -std=gnu99")
ENDFOREACH()

ADD_EXECUTABLE(cjet.bin
	${CJET_FILES}
	${CJET_LINUX_FILES}
)
ADD_DEPENDENCIES(cjet.bin REVISION_GEN)
TARGET_LINK_LIBRARIES(
	cjet.bin
	m
)

