# this one is important
SET(CMAKE_SYSTEM_NAME Linux)
#this one not so much
SET(CMAKE_SYSTEM_VERSION 1)

SET (CMAKE_C_COMPILER "gcc")
SET (CMAKE_CXX_COMPILER "g++")

SET (CMAKE_C_COMPILER "/opt/poky/1.5.1/sysroots/x86_64-pokysdk-linux/usr/bin/powerpc-poky-linux/powerpc-poky-linux-gcc")
SET (CMAKE_CXX_COMPILER "/opt/poky/1.5.1/sysroots/x86_64-pokysdk-linux/usr/bin/powerpc-poky-linux/powerpc-poky-linux-g++")

SET(CMAKE_C_FLAGS "-pipe -Wall -Wshadow -Wextra -Winit-self -Wstrict-overflow=5 -Wunused-result -Wcast-qual -Wcast-align -Wpointer-arith -Wformat=2 -Wwrite-strings -Wmissing-prototypes -std=c99 -pedantic" CACHE STRING "" FORCE)
#SET(CMAKE_C_FLAGS_RELEASE "-O2 -fomit-frame-pointer" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS_RELEASE "-O2 -flto -fomit-frame-pointer" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb" CACHE STRING "" FORCE)

IF(NOT CMAKE_BUILD_TYPE )
  SET(CMAKE_BUILD_TYPE RELEASE CACHE STRING "" FORCE )
ENDIF()

SET (CMAKE_EXE_LINKER_FLAGS "-Wl,-O2 -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--gc-sections" CACHE STRING "" FORCE)
#SET (CMAKE_EXE_LINKER_FLAGS "-Wl,-O2 -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--gc-sections" CACHE STRING "" FORCE)

MESSAGE (STATUS "Found gcc toolchain")

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
