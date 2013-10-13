project("cjet" C)

cmake_minimum_required(VERSION 2.8)

# SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -fomit-frame-pointer" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -flto -fwhole-program -fomit-frame-pointer" CACHE STRING "" FORCE)
# SET(CMAKE_C_FLAGS "-pipe -Wall -Wextra -pedantic -O2 -flto -fuse-linker-plugin -fomit-frame-pointer" CACHE STRING "" FORCE)

SET(CJET_FILES
	cJSON.c
	main.c
	parse.c
	peer.c
)

SET(GEN_MESSAGE_HASHES
	gen_message_hashes/main.c
)

set(DYNLIBS
	-lm
)

ADD_EXECUTABLE(cjet.bin ${CJET_FILES})
ADD_EXECUTABLE(gen_message_hashes.bin ${GEN_MESSAGE_HASHES})

target_link_libraries (
	cjet.bin
	${DYNLIBS}
)

