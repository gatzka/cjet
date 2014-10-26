# this one is important
SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_PROCESSOR arm)

SET(CJET_TOOLCHAIN_PATH /opt/linaro/gcc-linaro-arm-linux-gnueabihf-4.9-2014.09_linux/)

SET(triple arm-linux-gnueabihf)

SET(CMAKE_C_COMPILER   ${CJET_TOOLCHAIN_PATH}/bin/${triple}-gcc)
SET(CMAKE_CXX_COMPILER ${CJET_TOOLCHAIN_PATH}/bin/${triple}-g++)
SET(CMAKE_AR           ${CJET_TOOLCHAIN_PATH}/bin/${triple}-ar)
SET(CMAKE_LINKER       ${CJET_TOOLCHAIN_PATH}/bin/${triple}-ld)
SET(CMAKE_NM           ${CJET_TOOLCHAIN_PATH}/bin/${triple}-nm)
SET(CMAKE_OBJCOPY      ${CJET_TOOLCHAIN_PATH}/bin/${triple}-objcopy)
SET(CMAKE_OBJDUMP      ${CJET_TOOLCHAIN_PATH}/bin/${triple}-objdump)
SET(CMAKE_RANLIB       ${CJET_TOOLCHAIN_PATH}/bin/${triple}-ranlib)
SET(CMAKE_STRIP        ${CJET_TOOLCHAIN_PATH}/bin/${triple}-strip)

SET(CMAKE_FIND_ROOT_PATH ${CJET_TOOLCHAIN_PATH}/arm-linux-gnueabihf/libc/)
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

