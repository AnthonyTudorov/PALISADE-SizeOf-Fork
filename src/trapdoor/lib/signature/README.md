PALISADE Lattice Cryptography Library
=====================================

[License Information](License.md)

[Contact Information](Contact.md)

Document Description
===================
This document is intended to describe the overall design, design considerations and structure of the signature directory in the PALISADE lattice crypto library.

Signature Directory Description
=============================

Directory Objective
-------------------
The lattice directory support the digital signing operations in the library. It is yet to be completed and currently supports only Ring-LWE variant of the GPV signature scheme with trapdoors.

The signature layer is part of the crypto layer in the library.
The signature layer is intended to make calls to lower layers that support math operations, such as modulus and ring arithmetic or utilities such as hashing.  

File Listing
------------

* Classes files
	- [lwesign.h](src/crypto/signature/lwesign.h) This file contains the classes that is part of the GPV signature scheme with trapdoors. It is not final and will be changed once the class structure of supported signature schemes will be determined. Currenty it holds all of the classes regarding the scheme.
* Documentation files
  - [README.md](src/crypto/signature/README.md): This file.



Directory Description
=====================

The primary objective of the code in this directory is to generate and verify digital signatures based upon the Ring-LWE variant of the GPV signature scheme with trapdoors.It utilizes polynomial ring elements with power-of-2 dimensionality.

The main class is LPSignatureSchemeGPV, where anything related to digital signature (key generation, signing and verification) is called from. The class is templated for support for different ring types but this support is not yet implemented.

The classes LPSignKeyGPV and LPVerificationKey represents the keys that are used for signing and verification processes respectively. These classes are templated for support for different ring types but this support is not yet implemented.

LPSignatureParameters class is a container of parameters that are required during the signing and verification process.

FORMAT
------

Format used during the calculations between polynomial rings follows the requirements of the lower layers of the library and does not introduce anything new.

ASSUMPTIONS
===========

* Current signature scheme supports only one type of rings. Support for other rings is yet to be implemented.
* Perturbation matrix generation step in key generation is significantly improved and the signature supports higher dimensions. However, this step mainly consists of large floating point matrix calculations therefore it still needs time & memory.