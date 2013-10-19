project("cjet" C)

cmake_minimum_required(VERSION 2.8)

SET(CJET_FILES
	cJSON.c
	jet_config.c
	main.c
	parse.c
	peer.c
	response.c
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

