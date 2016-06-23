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

PalisadeCryptoContext.parms
testall

leaktester.cpp
palisade.cpp
plaintextMessage
PrettyJson.cpp
Source.cpp
Source_dcrt.cpp
Source_json.cpp
Source_presim.cpp
Source_presim2.cpp
testJson.cpp
testJson.h

* Parameter classes files
  - [elemparams.h](src/lattice/elemparams.h): This header file is a simple class to contain ring element parameters.
  - [ilparams.h](src/lattice/ilparams.h), [ilparams.cpp](src/lattice/ilparams.cpp): This pair of files represents a parameter class for the basic single-CRT lattice parameters.  This class inherits from the class in [elemparams.h](src/lattice/elemparams.h).
  - [ildcrtparams.h](src/lattice/ildcrtparams.h): This file represents a parameter class for the more advanced and computationally efficient double-CRT lattice parameters.  This class inherits from the class in [ilparams.h](src/lattice/ilparams.h), [ilparams.cpp](src/lattice/ilparams.cpp).
* Element classes files
  - [ilelement.h](src/lattice/ilelement.h): This file presents a basic interface class for elements from ideal lattices.
  - [ilvector2n.h](src/lattice/ilvector2n.h), [ilvector2n.cpp](src/lattice/ilvector2n.cpp): These files present a basic class for elements from ideal lattices using a single-CRT representation assuming a ring dimension that is a power of 2.  This class inherits from the class in [ilelement.h](src/lattice/ilelement.h).
  - [ilvectorarray2n.h](src/lattice/ilvectorarray2n.h), [ilvectorarray2n.cpp](src/lattice/ilvectorarray2n.cpp): These files present a basic class for elements from ideal lattices using a double-CRT representation assuming a ring dimension that is a power of 2.  This class inherits from the class in [ilelement.h](src/lattice/ilelement.h).
* Documentation files
  - [README.md](src/lattice/README.md): This file.

