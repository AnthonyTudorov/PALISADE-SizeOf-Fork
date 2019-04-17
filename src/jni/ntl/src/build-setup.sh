#!/bin/sh

if [ "$(uname)" == "Darwin" ]; then
	BHOST=darwin-x86_64
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
	BHOST=linux-x86_64
else
	echo "Cannot build on windows"
	exit 1
fi

export NDK_DIR=${NDK_DIR:-"$HOME/Desktop/android-ndk-r16b/"}
ORIG_PATH=$PATH

case "$1" in

armeabi)
	export ANDROID_ABI=armeabi
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/$BHOST/bin
	make all
	if [ $? -eq 0 ]; then
		cp -r ../include/NTL ../prebuilt/$ANDROID_ABI
		arm-linux-androideabi-strip --strip-unneeded ntl.a
		cp ntl.a ../prebuilt/$ANDROID_ABI/libntl.a
		cp libntl.so ../prebuilt/$ANDROID_ABI/libntl.so
	fi
	;;

armeabi-v7a)
	export ANDROID_ABI=armeabi-v7a
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/$BHOST/bin
	make all
	if [ $? -eq 0 ]; then
		cp -r ../include/NTL ../prebuilt/$ANDROID_ABI
		arm-linux-androideabi-strip --strip-unneeded ntl.a
		cp ntl.a ../prebuilt/$ANDROID_ABI/libntl.a
		cp libntl.so ../prebuilt/$ANDROID_ABI/libntl.so
	fi
	;;

arm64-v8a)
	export ANDROID_ABI=arm64-v8a
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/aarch64-linux-android-4.9/prebuilt/$BHOST/bin
	make all
	if [ $? -eq 0 ]; then
		cp -r ../include/NTL ../prebuilt/$ANDROID_ABI
		aarch64-linux-android-strip --strip-unneeded ntl.a
		cp ntl.a ../prebuilt/$ANDROID_ABI/libntl.a
		cp libntl.so ../prebuilt/$ANDROID_ABI/libntl.so
	fi
	;;

x86_64)
	export ANDROID_ABI=x86_64
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/x86_64-4.9/prebuilt/$BHOST/bin
	make setup1
	make setup2
	make setup3
	make setup4
	#if [ $? -eq 0 ]; then
		#cp -r ../include/NTL ../prebuilt/$ANDROID_ABI
		#x86_64-linux-android-strip --strip-unneeded ntl.a
		#cp ntl.a ../prebuilt/$ANDROID_ABI/libntl.a
		#cp libntl.so ../prebuilt/$ANDROID_ABI/libntl.so
	#fi
	;;

*)
	echo "You must specify target hardware abi: armeabi, armeabi-v7a, arm64-v8a, or x86_64"
	exit 1
	;;
esac

#make check
#make clobber
