## this script does the "prep" for building NTL
## it builds the header files by running the NTL
## test programs on an emulator or on a device

## you MUST have an emulator running OR have an actual phone connected

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
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/$BHOST/bin
	make setup1 setup2 setup3 setup4
	if [ $? -eq 0 ]; then
		rm -fr ../prebuilt/$ANDROID_ABI
		mkdir -p ../prebuilt/$ANDROID_ABI/NTL
		cp ../include/NTL/*.h ../prebuilt/$ANDROID_ABI/NTL
		cp GetTime.cpp GetPID.cpp ../prebuilt/$ANDROID_ABI
	fi
	;;

armeabi-v7a)
	export ANDROID_ABI=armeabi-v7a
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/$BHOST/bin
	make setup1 setup2 setup3 setup4
	if [ $? -eq 0 ]; then
		rm -fr ../prebuilt/$ANDROID_ABI
		mkdir -p ../prebuilt/$ANDROID_ABI/NTL
		cp ../include/NTL/*.h ../prebuilt/$ANDROID_ABI/NTL
		cp GetTime.cpp GetPID.cpp ../prebuilt/$ANDROID_ABI
	fi
	;;

arm64-v8a)
	export ANDROID_ABI=arm64-v8a
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/aarch64-linux-android-4.9/prebuilt/$BHOST/bin
	make setup1 setup2 setup3 setup4
	if [ $? -eq 0 ]; then
		rm -fr ../prebuilt/$ANDROID_ABI
		mkdir -p ../prebuilt/$ANDROID_ABI/NTL
		cp ../include/NTL/*.h ../prebuilt/$ANDROID_ABI/NTL
		cp GetTime.cpp GetPID.cpp ../prebuilt/$ANDROID_ABI
	fi
	;;

x86_64)
	export ANDROID_ABI=x86_64
	export PATH=$ORIG_PATH:$NDK_DIR/toolchains/x86_64-4.9/prebuilt/$BHOST/bin
	make setup1 setup2 setup3 setup4
	if [ $? -eq 0 ]; then
		rm -fr ../prebuilt/$ANDROID_ABI
		mkdir -p ../prebuilt/$ANDROID_ABI/NTL
		cp ../include/NTL/*.h ../prebuilt/$ANDROID_ABI/NTL
		cp GetTime.cpp GetPID.cpp ../prebuilt/$ANDROID_ABI
	fi
	;;

*)
	echo "You must specify target hardware abi: armeabi, armeabi-v7a, arm64-v8a, or x86_64"
	exit 1
	;;
esac

make clobber
