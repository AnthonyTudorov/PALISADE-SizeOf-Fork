#!/bin/bash

# TODO: cross-compile testsuite & run on a target device
# Building the tests without running them is easy; just do "make check TESTS=''"

cd src

if [ ! -x configure ]
then
  echo "Run this script from the GMP base directory"
  exit 1
fi

export NDK_DIR=${NDK_DIR:-"$HOME/Desktop/android-ndk-r16b"}
if [ ! -d ${NDK_DIR} ]
then
  echo "Please download and install the NDK_DIR, then update the path in this script."
  echo "  http://developer.android.com/sdk/ndk/index.html"
  exit 1
fi

# Extract an Android toolchain, if needed
export TARGET32="android-26"
export TARGET64="android-26"
export TOOLCHAIN32="/tmp/${TARGET32}-arm32"
export TOOLCHAIN64="/tmp/${TARGET64}-arm64"
if [ ! -d ${TOOLCHAIN32} ]
then
  echo "======= EXTRACTING TOOLCHAIN FOR ARM32 ======="
  ${NDK_DIR}/build/tools/make-standalone-toolchain.sh --toolchain=arm-linux-androideabi-4.9 --platform=${TARGET32} --install-dir=${TOOLCHAIN32} || exit 1
fi
if [ ! -d ${TOOLCHAIN64} ]
then
  echo "======= EXTRACTING TOOLCHAIN FOR ARM64 ======="
  ${NDK_DIR}/build/tools/make-standalone-toolchain.sh --toolchain=aarch64-linux-android-4.9 --platform=${TARGET64} --install-dir=${TOOLCHAIN64} || exit 1
fi

export PATH="${TOOLCHAIN32}/bin:${TOOLCHAIN64}/bin:${PATH}"
export LIBGMP_LDFLAGS='-avoid-version'
export LIBGMPXX_LDFLAGS='-avoid-version'

################################################################################################################

export BASE_CFLAGS='-O2 -g -pedantic -fomit-frame-pointer -Wa,--noexecstack -ffunction-sections -funwind-tables -no-canonical-prefixes -fno-strict-aliasing'

# LDFLAGS for 64-bit ARM
export LDFLAGS='-Wl,--no-undefined -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now'

# arm64-v8a
echo "======= COMPILING FOR arm64-v8a ======="
export CFLAGS="${BASE_CFLAGS} -fstack-protector-strong -finline-limit=300 -funswitch-loops"
./configure --prefix=/usr --disable-static --enable-cxx --build=x86_64-pc-linux-gnu --host=aarch64-linux-android MPN_PATH="arm64 generic"
sed -i.bak '/HAVE_LOCALECONV 1/d' ./config.h
make -j8 V=1 2>&1 | tee arm64-v8a.log
make install DESTDIR=$PWD/../prebuilt/arm64-v8a
( cd ../prebuilt/arm64-v8a && mv usr/lib/libgmp.so usr/lib/libgmpxx.so usr/include/gmp.h usr/include/gmpxx.h . && rm -rf usr )
make distclean

# LDFLAGS for 32-bit ARM
export LDFLAGS='-Wl,--fix-cortex-a8 -Wl,--no-undefined -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now'

# armeabi-v7a with neon (unsupported target: will cause crashes on many phones, but works well on the Nexus One)
export CFLAGS="${BASE_CFLAGS} -fstack-protector -finline-limit=64 -march=armv7-a -mfloat-abi=softfp -mfpu=neon -ftree-vectorize -ftree-vectorizer-verbose=2"
./configure --prefix=/usr --disable-static --enable-cxx --build=x86_64-pc-linux-gnu --host=arm-linux-androideabi MPN_PATH="arm/v6t2 arm/v6 arm/v5 arm generic"
sed -i.bak '/HAVE_LOCALECONV 1/d' ./config.h
make -j8 V=1 2>&1 | tee armeabi-v7a-neon.log
make install DESTDIR=$PWD/../prebuilt/armeabi-v7a-neon
( cd ../prebuilt/armeabi-v7a-neon && mv usr/lib/libgmp.so usr/lib/libgmpxx.so usr/include/gmp.h usr/include/gmpxx.h . && rm -rf usr )
make distclean

# armeabi-v7a
export CFLAGS="${BASE_CFLAGS} -fstack-protector -finline-limit=64 -march=armv7-a -mfloat-abi=softfp -mfpu=vfp"
./configure --prefix=/usr --disable-static --enable-cxx --build=x86_64-pc-linux-gnu --host=arm-linux-androideabi MPN_PATH="arm/v6t2 arm/v6 arm/v5 arm generic"
sed -i.bak '/HAVE_LOCALECONV 1/d' ./config.h
make -j8 V=1 2>&1 | tee armeabi-v7a.log
make install DESTDIR=$PWD/../prebuilt/armeabi-v7a
( cd ../prebuilt/armeabi-v7a && mv usr/lib/libgmp.so usr/lib/libgmpxx.so usr/include/gmp.h usr/include/gmpxx.h . && rm -rf usr )
make distclean

# armeabi
export CFLAGS="${BASE_CFLAGS} -fstack-protector -finline-limit=64 -march=armv5te -mtune=xscale -msoft-float -mthumb"
./configure --prefix=/usr --disable-static --enable-cxx --build=x86_64-pc-linux-gnu --host=arm-linux-androideabi MPN_PATH="arm/v5 arm generic"
sed -i.bak '/HAVE_LOCALECONV 1/d' ./config.h
make -j8 V=1 2>&1 | tee armeabi.log
make install DESTDIR=$PWD/../prebuilt/armeabi
( cd ../prebuilt/armeabi && mv usr/lib/libgmp.so usr/lib/libgmpxx.so usr/include/gmp.h usr/include/gmpxx.h . && rm -rf usr )
make distclean

exit 0
