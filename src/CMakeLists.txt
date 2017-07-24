CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(PROJECTNAME cjet)
PROJECT(${PROJECTNAME} C)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/)
INCLUDE(version)
GENERATE_VERSION(version)
INCLUDE(defaults)
INCLUDE(generate_doxygen)


CONFIGURE_FILE(linux/config/os_config.h.in ${PROJECT_BINARY_DIR}/generated/os_config.h)
CONFIGURE_FILE(cjet_config.h.in ${PROJECT_BINARY_DIR}/generated/cjet_config.h)
CONFIGURE_FILE(version.h.in ${PROJECT_BINARY_DIR}/generated/version.h)

SET(WARN_SWITCHES "-Wall -Wextra -Werror -Wshadow -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wformat=2 -Wwrite-strings -Wmissing-prototypes -pedantic")

SET(CMAKE_C_FLAGS "-pipe -fvisibility=hidden -fno-common ${WARN_SWITCHES}")

SET(CMAKE_C_FLAGS_RELEASE "-O3 -fno-asynchronous-unwind-tables")
IF(CMAKE_C_COMPILER_ID STREQUAL GNU)
        IF(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 5.0.0)
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
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wstrict-overflow=2 -Wl,-O3,--gc-sections,-s")
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl,-O0")

IF(NOT CMAKE_BUILD_TYPE)
        SET(CMAKE_BUILD_TYPE "Release")
ENDIF()

MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "Target Processor: ${CMAKE_SYSTEM_PROCESSOR}")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/)
INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR}/)

INCLUDE(hardening)

SET(CJET_FILES
        alloc.c
        authenticate.c
        base64.c
        buffered_socket.c
        config.c
        element.c
        fetch.c
        groups.c
        http-parser/http_parser.c
        http_connection.c
        http_server.c
        info.c
        jet_string.c
        json/cJSON.c
        parse.c
        peer.c
        response.c
        router.c
        sha1/sha1.c
        socket_peer.c
        table.c
        timer.c
        utf8_checker.c
        websocket.c
        websocket_peer.c
)

SET(CJET_LINUX_FILES
        linux/eventloop_epoll.c
        linux/jet_endian.c
        linux/jet_string.c
        linux/linux_io.c
        linux/random.c
        linux/timer_linux.c
)

SET(CJET_POSIX_FILES
        posix/auth_file.c
        posix/jet_string.c
        posix/log.c
        posix/main.c
        posix/socket.c
)

SET (CJET_ZLIB_FILES
        zlib/adler32.c
        zlib/deflate.c
        zlib/inffast.c
        zlib/inflate.c
        zlib/inftrees.c
        zlib/trees.c
        zlib/zutil.c
)

FOREACH(_file ${CJET_FILES})
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        STRING(SUBSTRING ${checksum} 0 8 checksum)
        SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum} -std=c99")
ENDFOREACH()

FOREACH(_file ${CJET_LINUX_FILES})
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        STRING(SUBSTRING ${checksum} 0 8 checksum)
        SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum} -D_GNU_SOURCE -std=c99")
ENDFOREACH()

FOREACH(_file ${CJET_POSIX_FILES})
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        STRING(SUBSTRING ${checksum} 0 8 checksum)
        SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum} -D_XOPEN_SOURCE=500 -std=c99")
ENDFOREACH()

FOREACH(_file ${CJET_ZLIB_FILES})
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        STRING(SUBSTRING ${checksum} 0 8 checksum)
        SET(WARN_SWITCHES "-Wnone")
        SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum} -std=c99")
ENDFOREACH()

ADD_EXECUTABLE(cjet
        ${CJET_FILES}
        ${CJET_LINUX_FILES}
        ${CJET_POSIX_FILES}
        ${CJET_ZLIB_FILES}
)

TARGET_LINK_LIBRARIES(
        cjet
        m
        crypt
)

INSTALL(TARGETS cjet RUNTIME DESTINATION bin)
