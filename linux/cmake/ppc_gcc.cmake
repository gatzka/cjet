# this one is important
SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_PROCESSOR powerpc)

SET(CJET_TOOLCHAIN_PATH /opt/poky/1.7.1/sysroots/)

SET(triple powerpc-poky-linux)

SET(CMAKE_C_COMPILER   ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-gcc)
SET(CMAKE_CXX_COMPILER ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-g++)
SET(CMAKE_AR           ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-ar)
SET(CMAKE_LINKER       ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-ld)
SET(CMAKE_NM           ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-nm)
SET(CMAKE_OBJCOPY      ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-objcopy)
SET(CMAKE_OBJDUMP      ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-objdump)
SET(CMAKE_RANLIB       ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-ranlib)
SET(CMAKE_STRIP        ${CJET_TOOLCHAIN_PATH}/x86_64-pokysdk-linux/usr/bin/${triple}/${triple}-strip)

SET(CMAKE_FIND_ROOT_PATH ${CJET_TOOLCHAIN_PATH}/ppc7400-poky-linux/)
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


