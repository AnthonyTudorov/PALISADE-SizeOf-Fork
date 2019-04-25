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

this will create several files under src/libs:

libs/arm64-v8a/libc++_shared.so
libs/arm64-v8a/libgmp.so
libs/arm64-v8a/libgtest.so
libs/arm64-v8a/libntl.so
libs/arm64-v8a/libPALISADEcore.so
libs/arm64-v8a/libPALISADEjni.so
libs/arm64-v8a/libPALISADEpke.so
libs/arm64-v8a/PALISADEunit
libs/x86_64/libc++_shared.so
libs/x86_64/libgmp.so
libs/x86_64/libgtest.so
libs/x86_64/libntl.so
libs/x86_64/libPALISADEcore.so
libs/x86_64/libPALISADEjni.so
libs/x86_64/libPALISADEpke.so
libs/x86_64/PALISADEunit

copy all of the .so files into the jniLibs directory of any app that wants to use the library

** The shell script BuildAndroidJar will create a file called PALISADE.jar in the libs directory. This jar
file is the Java side of the code in the libPALISADEjni library. Every app that wants to use PALISADE
from Java needs it

** The shell script PackageAndroidLibs will create a gzip'd tar file of all the libraries and the jar files

** PALISADEunit is a standalone unit test application for the phone. The shell script RunAndroidUnitTests will
push the necessary libs and the app to the simulator or to a connected phone and run them on the phone


