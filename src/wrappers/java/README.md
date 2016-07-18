PALISADE Lattice Cryptography Library - Java Wrappers
=====================================================

[License Information](License.md)

[Contact Information](Contact.md)

Document Description
===================
This document is intended to describe the JNI wrapper and Java test classes for the PALISADE lattice crypto library.

Demo Directory Description
==========================

Directory Objective
-------------------
This directory contains the JNI layer and Java classes to use it.

File Listing
------------

- [com_palisade_PalisadeCrypto.h](src/wrappers/java/com_palisade_PalisadeCrypto.h): header for the JNI routines
- [PalisadeCryptoWrapper.cpp](src/wrappers/java/PalisadeCryptoWrapper.cpp): JNI functions
- [PalisadeCrypto](src/wrappers/java/PalisadeCrypto): java source tree
- [PalisadeCrypto.java](src/wrappers/java/PalisadeCrypto/src/com/palisade/PalisadeCrypto.java): the Java side of the PalisadeCrypto JNI layer. In order to use Palisade from Java, you must create an instance of this class and use its methods. There is a main() function in this class that is a demo of all the functions and how they work
- [PalisadeKeypair.java](src/wrappers/java/PalisadeCrypto/src/com/palisade/PalisadeKeypair.java): class representing a new public/private keypair
- [- [README/md](src/wrappers/java/README.md): This file

Additional Instructions
-----------------------

Build the java wrapper by executing "make alljava"

To demonstrate the library after building it, run the following command from the root of the development tree:

java -cp bin/lib/PalisadeCrypto.jar -Djava.library.path=bin/lib com.palisade.PalisadeCrypto
