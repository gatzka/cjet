SET (CMAKE_C_COMPILER        "clang")
SET (CMAKE_CXX_COMPILER      "clang++")
SET (CMAKE_C_COMPILER "gcc")
SET (CMAKE_CXX_COMPILER "g++")

SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -flto -fwhole-program -fomit-frame-pointer" CACHE STRING "" FORCE)
# SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -fomit-frame-pointer" CACHE STRING "" FORCE)
# SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -flto -fuse-linker-plugin -fomit-frame-pointer" CACHE STRING "" FORCE)



MESSAGE (STATUS "Found gcc toolchain")

###set (BOOST_ROOT /opt/boost-1.52.0/)
# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search
# programs in the host environment
#set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
#set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
#set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

