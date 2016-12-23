PALISADE Lattice Cryptography Library - Demos
=============================================

[License Information](License.md)

[Contact Information](Contact.md)

Document Description
===================
This document is intended to describe the demo programs included with the PALISADE lattice crypto library.

Demo Directory Description
==========================

Directory Objective
-------------------
This directory contains demo programs that, when linked with the library, demonstrate the capabilities of the system

File Listing
------------

* Parameters
- [PalisadeCryptoContext.parms](src/demo/pre/PalisadeCryptoContext.parms): This file is a JSON document containing a number of different parameter sets. It is read by several of the demo programs

* Test Script
- [testall](src/demo/pre/testall): runs through several tests of the library using the "palisade" demo program. Testall can be run from the root of the build tree
- [plaintextMessage](src/demo/pre/plaintextMessage): a test plaintext message used by testall

* Demo programs
- [leaktester.cpp](src/demo/pre/leaktester.cpp): a throwaway program being used to test for leaks
- [palisade.cpp](src/demo/pre/palisade.cpp): a program designed to demonstrate the key generation, evaluation key generation, encryption, re-encryption, and decryption functionality of the library. If you run the command without any parameters it generates a help message. Results are serialized into flat files, and are deserialized when needed. The program will read the crypto context parms file, or will read a file that you provide. Note you can also tell the program to figure out what crypto parameters to use based on whatever serialized object you are reading at the start of your program.
- [PrettyJson.cpp](src/demo/pre/PrettyJson.cpp): a pretty-printer of serialized JSON files
- [Source.cpp](src/demo/pre/Source.cpp): test program for the library
- [Source_dcrt.cpp](src/demo/pre/Source_dcrt.cpp):
- [Source_json.cpp](src/demo/pre/Source_json.cpp): same as Source but also adds json testing if you pass it the -dojson argument
- [Source_presim.cpp](src/demo/pre/Source_presim.cpp):
- [Source_presim2.cpp](src/demo/pre/Source_presim2.cpp):
- [testJson.cpp](src/demo/pre/testJson.cpp): tests the serialization and deserialization of the keys and ciphertext
- [testJson.h](src/demo/pre/testJson.h): used by testJson.cpp

* Documentation files
  - [README.md](src/lattice/README.md): This file.

