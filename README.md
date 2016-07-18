PALISADE Lattice Cryptography Library
=====================================

[License Information](License.md)

[Contact Information](Contact.md)

[Library Contributors](Contributors.md)

This is a software library for general lattice crypto.  We implement this library in the following multiple layers:

* Math operations layer to support low-level modulus arithmetic.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice operations layer to support lattice operations and ring algebra.  This layer makes calls to the math operations layer.
* Crypto layer to contain multiple implementations of lattice encryption schemes, including PRE schemes, leveled homomorphic encryption schemes, lattice trapdoors and lattice signature schemes.

The library includes unit tests and several sample application demos.

The library is implemented in C++11.  We have tested it with the latest gcc and Visual Studio compilers.  The library depends on the latest version of boost.
