CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(PROJECTNAME cjet)
PROJECT(${PROJECTNAME} C)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/)
INCLUDE(version)
INCLUDE(defaults)

GENERATE_VERSION(version)

CONFIGURE_FILE(linux/config/os_config.h.in ${PROJECT_BINARY_DIR}/generated/os_config.h)
CONFIGURE_FILE(cjet_config.h.in ${PROJECT_BINARY_DIR}/generated/cjet_config.h)
CONFIGURE_FILE(version.h.in ${PROJECT_BINARY_DIR}/generated/version.h)

SET(WARN_SWITCHES "-Wall -Wextra -Werror -Wshadow -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wpointer-arith -Wformat=2 -Wwrite-strings -Wmissing-prototypes -pedantic")

SET(CMAKE_C_FLAGS "-pipe -fvisibility=hidden -fno-common ${WARN_SWITCHES}")

SET(CMAKE_C_FLAGS_RELEASE "-O2 -fno-asynchronous-unwind-tables")
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
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wstrict-overflow=2 -Wl,-O2,--gc-sections,-s")
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
        base64.c
        buffered_socket.c
        config.c
        fetch.c
        http-parser/http_parser.c
        http_connection.c
        http_server.c
        info.c
        json/cJSON.c
        parse.c
        peer.c
        response.c
        router.c
        sha1/sha1.c
        socket_peer.c
        state.c
        table.c
        websocket.c
        websocket_peer.c
)

SET(CJET_LINUX_FILES
        linux/eventloop_epoll.c
        linux/jet_endian.c
        linux/jet_string.c
        linux/linux_io.c
        linux/main.c
        linux/socket.c
        linux/timer.c
        linux/uuid.c
)

FOREACH(_file ${CJET_FILES})
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        STRING(SUBSTRING ${checksum} 0 8 checksum)
        SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum} -std=gnu99")
ENDFOREACH()

FOREACH(_file ${CJET_LINUX_FILES})
        FILE(SHA1 ${PROJECT_SOURCE_DIR}/${_file} checksum)
        STRING(SUBSTRING ${checksum} 0 8 checksum)
        SET_PROPERTY(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum} -D_GNU_SOURCE -std=gnu99")
ENDFOREACH()

ADD_EXECUTABLE(cjet
        ${CJET_FILES}
        ${CJET_LINUX_FILES}
)

TARGET_LINK_LIBRARIES(
        cjet
        m
)

INSTALL(TARGETS cjet RUNTIME DESTINATION bin)
