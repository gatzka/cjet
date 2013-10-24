SET (CMAKE_C_COMPILER "gcc")
SET (CMAKE_CXX_COMPILER "g++")

SET(CMAKE_C_FLAGS "-pipe -Wall -Wshadow -Wextra -Wformat=2 -Wwrite-strings -Wmissing-prototypes -std=c99 -pedantic" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS_RELEASE "-O2 -flto -fwhole-program -fomit-frame-pointer" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb" CACHE STRING "" FORCE)

IF(NOT CMAKE_BUILD_TYPE )
  SET(CMAKE_BUILD_TYPE RELEASE CACHE STRING "" FORCE )
ENDIF()

SET (CMAKE_EXE_LINKER_FLAGS "-Wl,-O2 -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--gc-sections" CACHE STRING "" FORCE)

MESSAGE (STATUS "Found gcc toolchain")

