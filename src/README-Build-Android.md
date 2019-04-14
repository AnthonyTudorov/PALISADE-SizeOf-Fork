in order to build for Android, you MUST have android-ndk-r16b

these notes assume you've placed it in a folder named android-ndk-r16b on your
desktop

First you may need to build the NTL library from source:
1. start the two-six emulator from the command line (it's needed for
some of the configuration)
2. cd jni/ntl/src
3. ./build.sh

Then, back up in this directory (src), run:

~/Desktop/android-ndk-r16b/ndk-build NDK_PROJECT_PATH=$(pwd) NDK_APPLICATION_MK=$(pwd)/Application.mk APP_BUILD_SCRIPT=$(pwd)/Android.mk 

(you can give it the augument -j4 or -j8 to parallelize the make)

this will place a bunch of .so files into libs/x86_64:

libc++_shared.so
libPALISADEcore.so
libPALISADEpke.so
libgmp.so
libPALISADEjni.so

copy all into the jniLibs directory of the app
