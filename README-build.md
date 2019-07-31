Effective release 1.6, we have transitioned to building with CMake.

You must have cmake installed on your machine in order to build PALISADE.

We have transitioned to the use of submodules. The first time you clone PALISADE,
or the first time you change to this release, you may need to run the following commands

	git submodule sync --recursive
	git submodule update --init  --recursive

CMake will check that all required build tools are installed.

A cmake build can be run in any directory. Once you select a directory in which to build,
you simply run cmake and provide it the root directory of the source.

To run builds in a subdirectory named "build":

	mkdir build
	cd build
	cmake ..

This will create all the necessary makefiles. If you say "make help", all available targets are printed.

We also make use of git submodules for many of the pieces of code from third-party sources.
The cereal, google-benchmark, google-test and gperftools code are all git submodules.

If you want to use the tcmalloc package, you must

	make tcm

If you don't want to use tcmalloc any more, you must run

	make tcm_clean

There is one big difference between the old scheme for running make and the new scheme,
The difference has to do with the third-party GMP and NTL libraries. The user MUST build these
libraries one time, with separate commands:

	make gmp_unpack
	make ntl_unpack

	make gmp_all
	make ntl_all

The unpack targets force an unpacking of zipped distribution files. The all targets build the libraries.
If you would like to force a rebuild of one of these third-party libraries, you can "make gmp_clobber" or
"make ntl_clobber" to reset all the files. You will need to re-unpack and then build the all target.

Once this is completed, you can "make all" to make the entire PALISADE distribution.

There is no longer a giant unit test executable that runs every single test. You can still "make testall",
which really means "run the unit test for each component".

The "make clean" removes all build products (but not the third-party libraries). "make clobber" undoes the third-party
build products as well as PALISADE

Running "make install" installs executables, etc onto your machine; you probably need "sudo make install"
unless you are specifying some other install location. You can change the install location by running
"cmake -DCMAKE_INSTALL_PREFIX=/your/path".

Each component (core, pke, abe, trapdoor, signature, wip) has a set of common targets defined.
You can make allX, allXdemos, testX, or Xinfo, where X is the component (for example, make testpke will
build and run the pke unit tests).

Note that there is no longer a separate clean target for each component. You cannot, for example, "make cleancore".
If you need to do this, remove everything under build/src/core

MSYS2/MINGW64 instructions
===================

Download and install MSYS2 from http://www.msys2.org/ using default settings. Start the MSYS2 MINGW 64-bit shell and execute the following command

	pacman -Syu

to update all packages (you may need to run it twice as it often fails the first time; just reopen the console and reenter the command. This may also happen for the other installs below).

Run the following commands to install all pre-requisites 

	pacman -S mingw-w64-x86_64-gcc
	pacman -S mingw-w64-x86_64-cmake
	pacman -S autoconf
	pacman -S make

for GMP and NTL

	pacman -S tar
	pacman -S lzip

Use the following comnand to run cmake

	cmake .. -G"Unix Makefiles"

update ORIGINAL_PATH variable in c:\msys64\etc\profile to point to "lib" 

Follow the instructions above for other CMAKE/MAKE-related steps.
