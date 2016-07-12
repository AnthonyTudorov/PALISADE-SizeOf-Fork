PALISADE Lattice Cryptography Library
=====================================

[License Information](License.md)

[Contact Information](Contact.md)

Document Description
===================
This document is intended to describe the overall design, design considerations and structure of the lattice directory in the PALISADE lattice crypto library.

Lattice Directory Description
=============================

Directory Objective
-------------------
The lattice directory support the lattice layer operations in the library.  As such, it is intended to be used to represent polynomial rings and support operations over polynomial rings.

This lattice layer is a middle layer in the library.
The lattice layer supports higher-level calls for operations on ring elements necessary for lattice cryptography.
The lattice layer is intended to make calls to lower layers that support math operations, such as modulus and ring arithmetic.  

File Listing
------------

* Parameter classes files
  - [elemparams.h](src/lib/lattice/elemparams.h): This header file is a simple class to contain ring element parameters.
  - [ilparams.h](src/lib/lattice/ilparams.h), [ilparams.cpp](src/lib/lattice/ilparams.cpp): This pair of files represents a parameter class for the basic single-CRT lattice parameters.  This class inherits from the class in [elemparams.h](src/lib/lattice/elemparams.h).
  - [ildcrtparams.h](src/lib/lattice/ildcrtparams.h): This file represents a parameter class for the more advanced and computationally efficient double-CRT lattice parameters.  This class inherits from the class in [ilparams.h](src/lib/lattice/ilparams.h), [ilparams.cpp](src/lib/lattice/ilparams.cpp).
* Element classes files
  - [ilelement.h](src/lib/lattice/ilelement.h): This file presents a basic interface class for elements from ideal lattices.
  - [ilvector2n.h](src/lib/lattice/ilvector2n.h), [ilvector2n.cpp](src/lib/lattice/ilvector2n.cpp): These files present a basic class for elements from ideal lattices using a single-CRT representation assuming a ring dimension that is a power of 2.  This class inherits from the class in [ilelement.h](src/lib/lattice/ilelement.h).
  - [ilvectorarray2n.h](src/lib/lattice/ilvectorarray2n.h), [ilvectorarray2n.cpp](src/lib/lattice/ilvectorarray2n.cpp): These files present a basic class for elements from ideal lattices using a double-CRT representation assuming a ring dimension that is a power of 2.  This class inherits from the class in [ilelement.h](src/lib/lattice/ilelement.h).
* Documentation files
  - [README.md](src/lib/lattice/README.md): This file.



Directory Description
=====================

The primary objective of the code in this directory is to represent polynomial ring elements and manipulations on these elements.  The current implementations support polynomial rings that are of dimension a power of two (e.g. x^n + 1 where n is a power of 2).  A polynomial ring is defined as Rq := R/qR = Zq[X]/(f(X)), with f(X) a mononic irreducable polynomial of degree n, and q an integer modulus.

The two main data classes in this layer are ILVector2n and ILVectorArray2n. Both are designed to represent polynomial ring elements with power-of-2 dimensionality.  

The primary differences between ILVector2n and ILVectorArray2n are that ILVector2n uses single-CRT representation and ILVectorArray2n uses double-CRT representation.  In practice, this means that ILVector2n uses a single large modulus q, while  ILVectorArray2n uses multiple smaller moduli.  Hence, ILVector2n runs slower than ILVectorArray2n because ILVectorArray2n operations can be easier to fit into the native bitwidths of commodity processors.

ILVector2n and ILVectorArray2n implement the interface ILElement.  If new ring polynomials classes need to be built, we recommend building from ILElement, as we did with ILVector2n and ILVectorArray2n.

Supporting ILVector2n and ILVectorArray2n are the classes ILParams and ILDCRTParams which respectively contain parameters for the ring element representations.  In the case of ILVector2n, this includes the order, modulus and root of unity.  In the case of ILVectorArray2n, this includes the order, double-CRT width, moduli and roots of unity.

ILParams and ILDCRTParams implement the interface ElemParams.  If new ring polynomials classes need to be built, we recommend building from ElemParams, as we did with ILParams and ILDCRTParams.

FORMAT
------
The coefficients of the polynomial ring, in their initial form, are just coefficients. Translated into one of ILVector2n or ILVectorArray2n, can be simply seen
as vector's representing polynomial rings.

We internally represent polynomial ring elements as being either in coefficient or evaluation format.  The initial or raw format, is noted as COEFFICIENT through out the code. By applying the Chinese-Remainder-Transform (CRT), which is a Number Theoretic Transform (NTT)  and variant of the Discrete Fourier Transform (DFT), we convert the ring elements into the EVALUATION format. The EVALUATION format, with respect to multiplying two or more ring polynomials, allows us to do element-wise multiplication on the vectors.

Note that it is generally computationally less expensive to carry on all operations in the evaluation former.  However, the CRT and inverse CRT operations take O(nlogn) time using current best known algorithms, where n is the ring dimension.

ASSUMPTIONS
===========

* It is assumed that any scalar or vector operation such as multiplication, addition etc. done on one or more operations contain the same params.
  - Checks need to be added to the code to test the compatibility of parameters.
* Multiplication is currently only implemented in the EVALUATION format.
  - Code needs to be added to either implement COEFFICIENT format multiplication, or guard against COEFFICIENT format multiplication being called.