PALISADE Lattice Cryptography Library
=====================================

[License Information](License.md)

[Contact Information](Contact.md)

Document Description
===================
This document is intended to describe the overall design, design considerations and structure of the lattice directory in the PALISADE lattice crypto library.

Lattice Directory Description
=============================

OBJECTIVE
---------
The lattice directory support the lattice layer operations in the library.  As such, it is intended to be used to represent polynomial rings and support operations over polynomial rings.

This lattice layer is a middle layer in the library.
The lattice layer supports higher-level calls for operations on ring elements necessary for lattice cryptography.
The lattice layer is intended to make calls to lower layers that support math operations, such as modulus and ring arithmetic.  

File Listing
------------

* Parameter classes files
  - [elemparams.h](src/lattice/elemparams.h): This header file is a simple class to contain ring element parameters.
  - [ilparams.h](src/lattice/ilparams.h), [ilparams.cpp](src/lattice/ilparams.cpp)
  - [ildcrtparams.h](src/lattice/ildcrtparams.h)
* Element classes files
  - [ilelement.h](src/lattice/ilelement.h)
  - [ilvector2n.h](src/lattice/ilvector2n.h), [ilvector2n.cpp](src/lattice/ilvector2n.cpp)
  - [ilvectorarray2n.h](src/lattice/ilvectorarray2n.h), [ilvectorarray2n.cpp](src/lattice/ilvectorarray2n.cpp)
* Documentation files
  - [README.md](src/lattice/README.md)



Description
-----------

 is to represent a polynomial ring. Thus far, we only support polynomial rings modulus a power of two polynomial (e.g. x^n + 1 where n is a power of 2).

The two main data structures in this layer, ILVectorArray2n and ILVector2n represent these polynomials. A polynomial ring is defined as
Rq := R/qR = Zq[X]/(f(X)), with f(X) a mononic irreducable polynomial of degree n, and q an integer modulus. Both data structures represent a polynomial-ring.

TERMINOLOGY
-----------
Ring Dimension: The degree of the polynomial ring (denoted as n).

Cylotomic order: The power of X in f(X). Note that in the special case of polynomial rings modulus a power of two polynomial, the cyclotomic order is twice the ring dimension.

Both ILVector2n and ILVectorArray2n represent polynomial rings. Both have BigBinaryVector(s), with each index of the vector representing a coefficient of the
polynomial ring or e.g. index 1 would correspond 1 would correspond to the coefficient of x^1
and index n-1 to x^(n-1)). Before we explain the difference between the two, let us look at the the different formats the coefficients can have.

FORMAT
------
The coefficients of the polynomial ring, in their initial form, are just coefficients. Translated into one of ILVector2n or ILVectorArray2n, can be simply seen
as vector's representing polynomial rings. Their initial or raw format, is noted as COEFFICIENT through out the code. While in coefficient format multiplication
is polynomial multiplication.  Applying the Chinese-Remainder-Transform (CRT), which is based on the fast fourier transform, we obtain the EVALUATION FORMAT. The EVALUATION
format, with respect to multiplying two or more ring polynomials, allows us to do element-wise multiplication on the vectors. Note that the CRT operation takes
O(nlogn) time, where n is the size of the ring dimension.

Now let us look at the high level diagram of this layer:

-ElemParams
  -ILParams
  -ILDCRTParams
-ILElement
 -ILVector2n
 -ILVectorArray2n

HIGH LEVEL EXPLANATION
----------------------
As it can be seen in the diagram above, there are two parent classes, Elemparams and ILElement.

Elemparams: The parent class for parameters of ILElement.
ILElement: The parent class for the data structures ILVector2n and ILVectorArray2n.

Each ILElement class has it's own corresponding ElemParams class.

ILVector2n and ILParams: The class itself stands for Ideal Lattice Vector. This class has three private variables:
- BigBinaryVector *m_values;
- Format m_format;
- ILParams m_params;

As discussed above, the m_values holds the coefficients of the polynomial ring. The format specifies whether it is in Coefficient or Evaluation form.
The params (ILParams) holds an integer q, which is the integer modulus of the polynomial ring (under objective), the root of unity based (to calculate the CRT) and the cyclotomic order.


ILVectorArray2n and ILDCRTParams: ILDCRT stands for Ideal Lattice Chinese Remainder Transform. ILVectorArray2n has the following private variables:
-std::vector<ILVector2n> m_vectors;
-ILDCRTParams m_params;
-Format m_format;

ILVectorArray2n breaks down a polynomial represented in with a single vector (ILVector2n), into multiple vectors. These multiple vectors are represented as an ILVector2ns.
ILVectorArray2n's ILDCRTParam, requires a chain of moduli (q1,q2...,qt), where t is the number of vectors, denoted as towers. Each of these moduli will be the respective modulus
of the ILVector2ns. The reason ILVectorArray2n exists is for performance. The q1...qt values are smaller moduli (than if it were to be in an ILVector2n).


ASSUMPTIONS
-----------
- It is assumed that any scalar or vector operation such as multiplication, addition etc. done on one or more operations contain the same params.
- Vector Multiplication is only valid in EVALUATION format.
