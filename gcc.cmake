SET (CMAKE_C_COMPILER "gcc")
SET (CMAKE_CXX_COMPILER "g++")

SET(CMAKE_C_FLAGS "-pipe -Wall -Wshadow -Wextra -Wformat=2 -Wwrite-strings -std=c99 -pedantic -O2 -flto -fwhole-program -fomit-frame-pointer" CACHE STRING "" FORCE)
#SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -Wwrite-strings -std=c99 -pedantic -O0 -ggdb" CACHE STRING "" FORCE)
SET (CMAKE_EXE_LINKER_FLAGS "-Wl,-O2 -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--gc-sections" CACHE STRING "" FORCE)

MESSAGE (STATUS "Found gcc toolchain")

