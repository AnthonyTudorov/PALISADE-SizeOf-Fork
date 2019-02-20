#!/bin/sh

export NDK_DIR=$HOME/Desktop/android-ndk-r16b/
ORIG_PATH=$PATH

cd src

case "$1" in

armeabi)
	export ANDROID_ABI=armeabi
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin
	./configure --host=arm-linux-androideabi --prefix=$(pwd)/../prebuilt/$ANDROID_ABI
	if [ $? -eq 0 ]; then
		make 
		if [ $? -eq 0 ]; then
			make install
		fi
	fi
	;;

armeabi-v7a)
	export ANDROID_ABI=armeabi-v7a
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin
	./configure --host=arm-linux-androideabi --prefix=$(pwd)/../prebuilt/$ANDROID_ABI
	if [ $? -eq 0 ]; then
		make 
		if [ $? -eq 0 ]; then
			make install
		fi
	fi
	;;

arm64-v8a)
	export ANDROID_ABI=arm64-v8a
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin
	./configure --host=aarch64-linux-android --prefix=$(pwd)/../prebuilt/$ANDROID_ABI
	if [ $? -eq 0 ]; then
		make 
		if [ $? -eq 0 ]; then
			make install
		fi
	fi
	;;

x86_64)
	export ANDROID_ABI=x86_64
	mkdir -p ../prebuilt/$ANDROID_ABI
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/x86_64-4.9/prebuilt/linux-x86_64/bin
	./configure --host=x86_64-linux-android --prefix=$(pwd)/../prebuilt/$ANDROID_ABI
	if [ $? -eq 0 ]; then
		make 
		if [ $? -eq 0 ]; then
			make install
		fi
	fi
	;;

*)
	echo "You must specify target hardware abi: armeabi, armeabi-v7a, arm64-v8a, or x86_64"
	exit 1
	;;
esac

make clean
