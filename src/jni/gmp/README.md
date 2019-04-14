This directory is used to build the GMP library for Android. It builds from src (in the src directory),
and it places the build products into subdirectories of prebuilt.

The GMP library is versiobn 6.1.2. The contents of src should be an identical copy of third-party/distros/gmp-6.1.2

The build is run using Android NDK version r16b

The build scripts expect that the NDK is in the folder Desktop/android-ndk-r16b

If your NDK is in a different place, set the variable NDK to the pathname where your
NDK is located, and export NDK.

To build from source, run the following two shell scripts:

compile-gmp-arm.sh
compile-gmp-x86.sh

The results of running these scripts is archived in the GIT repo, so this build should not need to be rerun.
