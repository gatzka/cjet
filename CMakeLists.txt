project("cjet" C)

cmake_minimum_required(VERSION 2.8)

SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -fomit-frame-pointer" CACHE STRING "" FORCE)

SET(CJET_FILES
	cJSON.c
	main.c
	peer.c
)

set(DYNLIBS
	-lm
)

ADD_EXECUTABLE(cjet.bin ${CJET_FILES})

target_link_libraries (
	cjet.bin
	${DYNLIBS}
)

