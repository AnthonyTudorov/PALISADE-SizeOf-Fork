in order to build for Android, you MUST have android-ndk-r16b

these notes assume you've placed it in a folder named android-ndk-r16b on your
desktop

in this directory (src), run:

~/Desktop/android-ndk-r16b/ndk-build NDK_PROJECT_PATH=$(pwd) NDK_APPLICATION_MK=$(pwd)/Application.mk APP_BUILD_SCRIPT=$(pwd)/Android.mk ``

this will place a bunch of .so files into libs/x86_64:

libc++_shared.so
libPALISADEcore.so
libPALISADEpke.so
libgmp.so
libPALISADEjni.so

copy all into the jniLibs directory of the app
