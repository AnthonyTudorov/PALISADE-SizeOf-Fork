set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_PROCESSOR x86)

set(CROSS_TRIPLE i686-linux-android CACHE STRING "cross compile target")
set(tools /home/palisade/Android/Sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64)
set(CMAKE_C_COMPILER ${tools}/bin/${CROSS_TRIPLE}26-clang)
set(CMAKE_CXX_COMPILER ${tools}/bin/${CROSS_TRIPLE}26-clang++)
set(CMAKE_LD ${tools}/bin/${CROSS_TRIPLE}-ld)
set(CMAKE_AR ${tools}/bin/${CROSS_TRIPLE}-ar)
set(CMAKE_RANLIB ${tools}/bin/${CROSS_TRIPLE}-ranlib)
set(CMAKE_C_FLAGS "-march=i686 -mtune=intel -mssse3 -mfpmath=sse -m32 -fPIE -fPIC")
set(CMAKE_LD_FLAGS -pie)

set(CMAKE_FIND_ROOT_PATH ${tools})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(NTLCROSS "HOST=${CROSS_TRIPLE} NATIVE=off CXX=${CMAKE_CXX_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB}" CACHE STRING "force NTL cross compile")
