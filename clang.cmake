SET (CMAKE_C_COMPILER        "clang")
SET (CMAKE_CXX_COMPILER      "clang++")

SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -Wwrite-strings -pedantic -O2 -fomit-frame-pointer" CACHE STRING "" FORCE)
# SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -Wwrite-strings -pedantic -O2 -flto -use-gold-plugin -fomit-frame-pointer" CACHE STRING "" FORCE)

MESSAGE (STATUS "Found CLANG toolchain")

