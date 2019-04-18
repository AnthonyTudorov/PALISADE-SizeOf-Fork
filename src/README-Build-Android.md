in order to build for Android, you MUST have android-ndk-r16b

these notes assume you've placed it in a folder named android-ndk-r16b on your
desktop

First, build the gmp library from source
1. cd jni/gmp
2. follow the instructions in the readme

Then, build the NTL library from source:
1. cd jni/ntl
2. follow the instructions in the readme

Then, back up in this directory (src), run:

~/Desktop/android-ndk-r16b/ndk-build NDK_PROJECT_PATH=$(pwd) NDK_APPLICATION_MK=$(pwd)/Application.mk APP_BUILD_SCRIPT=$(pwd)/Android.mk 

(you can give it the augument -j4 or -j8 to parallelize the make)

this will place a bunch of .so files into subdirectories of libs:

libc++_shared.so
libPALISADEcore.so
libPALISADEpke.so
libgmp.so
libPALISADEjni.so

copy all into the jniLibs directory of the app
