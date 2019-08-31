PALISADE Lattice Cryptography Library
=====================================

PALISADE is a general lattice cryptography library that currently includes efficient implementations of the following lattice cryptography capabilities:
* Homomorphic Encryption (HE): Brakerski/Fan-Vercauteren (3 variants), Brakerski-Gentry-Vaikuntanathan, and Stehle-Steinfeld schemes
* Proxy Re-Encryption for all HE schemes
* Digital Signature
* Identity-Based Encryption
* Ciphertext-Policy Attribute-Based Encryption

PALISADE is a cross-platform C++11 library supporting Linux, Windows, and macOS. The supported compilers are g++ and clang++. 

The library also includes unit tests and sample application demos.

PALISADE is available under the BSD 2-clause license.

The library is based on modular architecture with the following layers:

* Math operations layer supporting low-level modular arithmetic, number theoretic transforms, and integer sampling.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice operations layer supporting lattice operations, ring algebra, and lattice trapdoor sampling. 
* Crypto layer containing efficient implementations of lattice cryptography schemes.
* Encoding layer supporting multiple plaintext encodings for cryptographic schemes.

A major focus is on the usability of the schemes. For instance, all HE schemes use the same common API, and are implemented using runtime polymorphism.

PALISADE implements efficient Residue Number System (RNS) algorithms to achieve high performance, e.g., PALISADE was used as the library for a winning genome-wide association studies solution at iDASH’18. 

By default, the library is built without external dependencies. But the user is also provided options to add GMP/NTL and/or tcmalloc third-party libraries if desired.

Further information about PALISADE:

[License Information](License.md)

[Contact Information](Contact.md)

[Library Contributors](Contributors.md)

[Library Wiki with documentation](https://gitlab.com/palisade/palisade-development/wikis/home)


Build Instructions
=====================================

We use CMake to build PALISADE. The high-level (platform-independent) procedure for building PALISADE is as follows:

1. Install system prerequisites (if not already installed), including a C++ compiler with OMP support, cmake, make, and autoconf.

2. Clone the PALISADE repo to your local machine.

3. Download information about submodules by running the following commands (PALISADE downloads submodules for cereal, google-benchmark, google-test, and gperftools open-source libraries):
```
git submodule sync --recursive
git submodule update --init  --recursive
```
	
4. Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are:
```
mkdir build
cd build
cmake ..
```
	
Note that cmake will check for any system dependencies that are needed for the build process. 
	
5. If you want to install any external libraries, such as NTL/GMP or tcmalloc, install these libraries.

6. Build PALISADE by running the following command (this will take few minutes; using the -j<threads> make command-line flag is suggested to speed up the build)
```
make
```
7. Install PALISADE in a system directoy (if desired or for production purposes)
```
make install
```	
You would probably need to run "sudo make install" unless you are specifying some other install location. You can change the install location by running
"cmake -DCMAKE_INSTALL_PREFIX=/your/path ..".

Testing and cleaning the build
-------------------

Run unit tests to make sure all capabilities operate as expected
```
make testall
```

Run sample code to test, e.g., 
```
bin/demo/pke/demo-bfvrns
```

To remove the files built by make, you can execute
```
make clean
```

Detailed information about building PALISADE
------------------------------
	
More detailed steps for some common platforms are provided in the following Wiki articles:

[Instructions for building PALISADE in Linux](wikis/Instructions-for-building-PALISADE-in-Linux)

[Instructions for building PALISADE in Windows](wikis/Instructions-for-building-PALISADE-in-Windows)

[Instructions for building PALISADE in macOS](wikis/Instructions-for-building-PALISADE-in-macOS)

PALISADE provides many CMake/make configuration options, such as installing specific modules of the library, compiling only libraries w/o any unit tests and demos, choosing the Debug mode for compilation, turning on/off NTL/GMP. These options are described in detail in the following Wiki article:

[Configuration flags to customize the build](wikis/Configuration-flags-to-customize-the-build) 