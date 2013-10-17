SET (CMAKE_C_COMPILER        "clang")
SET (CMAKE_CXX_COMPILER      "clang++")

SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -Wwrite-strings -pedantic -O2 -flto -fomit-frame-pointer" CACHE STRING "" FORCE)

MESSAGE (STATUS "Found CLANG toolchain")

###set (BOOST_ROOT /opt/boost-1.52.0/)
# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search
# programs in the host environment
#set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
#set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
#set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

