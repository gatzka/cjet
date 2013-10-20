SET (CMAKE_C_COMPILER "gcc")
SET (CMAKE_CXX_COMPILER "g++")

SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -Wwrite-strings -pedantic -O2 -flto -fwhole-program -fomit-frame-pointer" CACHE STRING "" FORCE)
SET (CMAKE_EXE_LINKER_FLAGS "-Wl,-O2 -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--gc-sections" CACHE STRING "" FORCE)
# SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -fomit-frame-pointer" CACHE STRING "" FORCE)
# SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -flto -fuse-linker-plugin -fomit-frame-pointer" CACHE STRING "" FORCE)

MESSAGE (STATUS "Found gcc toolchain")

