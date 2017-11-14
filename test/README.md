PALISADE Lattice Cryptography Library - Tests
=============================================

[License Information](License.md)

[Contact Information](Contact.md)

Document Description
===================
This document discusses the scripts and procedured in the test/ directory

Test Directory Description
==========================

Directory Objective
-------------------
This directory contains common test code and shell scripts useful for executing and automating
various PALISADE tests

File Listing
------------

* Demo programs
- [demo_fusion_simple.cpp](src/pke/demo/demo_fusion_simple.cpp): a demo program of multiparty FHE operations built on FV.
- [demo-cross-correlation.cpp](src/pke/demo/demo-cross-correlation.cpp): a demo program that demonstrates the use of serialization, DCRT, arbitrary cyclotomics, and packed encoding for an application that computes cross-correlation using inner products.
- [demo-crypt-pre-text.cpp](src/pke/demo/demo-crypt-pre-text.cpp): demonstrates use of PALISADE for encryption, re-encryption and decryption of text
- [demo-json.cpp](src/pke/demo/demo-json.cpp): demonstrates use of PALISADE encryption and decryption of vectors of integers, also illustrating the use of serializing information to text files
- [demo-linregress.cpp](src/pke/demo/demo-linregress.cpp): demonstrates performing linear regression on encrypted matrices
- [demo-packing.cpp](src/pke/demo/demo-packing.cpp): demonstrates inner product operations
- [demo-pke.cpp](src/pke/demo/demo-pke.cpp): demonstrates use of encryption across several schemes
- [demo-pre.cpp](src/pke/demo/demo-pre.cpp): demonstrates use of proxy re-encryption across several schemes
- [demo-she.cpp](src/pke/demo/demo-she.cpp): demonstrates SHE operations using several schemes
- [palisade.cpp](src/demo/pre/palisade.cpp): a program designed to demonstrate the key generation, evaluation key generation, encryption, re-encryption, and decryption functionality of the library. If you run the command without any parameters it generates a help message. Results are serialized into flat files, and are deserialized when needed. The program will read the crypto context parms file, or will read a file that you provide. Note you can also tell the program to figure out what crypto parameters to use based on whatever serialized object you are reading at the start of your program.


* test
- [build_all_backends.sh](test/build_all_backends.sh) builds the library for all valid math backends. Each backend is placed in its own bin directory, bin/backend-N, where N is the backend number. Passing the "force" argument causes a clean build
- [test_all_backends.sh](test/test_all_backends.sh) runs "make testall" on each of the backends built by build_all_backends.sh

- [build_cov_test_backends.sh](test/build_cov_test_backends.sh) builds the library for all valid math backends with coverage testing available. Each backend is placed in its own bin directory, bin/backend-N-cov, where N is the backend number. Passing the "force" argument causes a clean build
- [test_cov_backends.sh](test/test_cov_backends.sh) runs coverage test on each of the backends built by build_cov_test_backends

- [benchmark_all_backends.sh](test/benchmark_all_backends.sh) runs benchmarks against the backends built by build_all_backends.sh
- [valgrind_all_backends.sh](test/valgrind_all_backends.sh) runs valgrind on the unit tests for the backends built by build_all_backends.sh

* test/include:
- [gtest](test/include/gtest) contains all 
