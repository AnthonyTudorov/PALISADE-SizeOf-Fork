/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>,Jerry Ryan <gwryan@njit.edu>, Dave Cousins
 * @version 00_03
 *
 * @section LICENSE
 * 
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met: 1. Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.  2. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This file contains the functionality to switch between math backends
 */

#ifndef LBCRYPTO_MATH_BACKEND_H
#define LBCRYPTO_MATH_BACKEND_H
 
/*! Define the underlying default math implementation being used by defining MATHBACKEND */

// Each math backend is defined in its own namespace, and can be used at any time by referencing
// the objects in its namespace

// Selecting a math backend by defining MATHBACKEND means defining which underlying implementation
// is the default BigBinaryInteger and BigBinaryVector

// note that we #define how many bits the underlying integer can store as a guide for users of the backends

// MATHBACKEND 1
//		This is an old deprecated implementation, DO NOT USE

// MATHBACKEND 2
// 		Uses cpu_int:: definition as defaults

// MATHBACKEND 3
// 		This uses exp_int:: definition with uint32_t underlying size as defaults
// 			new dynamicly allocated backend and support uint32_t and uint64_t on linux
// 			This backend supports arbitrary bitwidths; no memory pool is used; can grow up to RAM limitation

// MATHBACKEND 4
// 		This uses exp_int:: definition with uint64_t underlying size as defaults

// MATHBACKEND 5
//		This is an old deprecated implementation, DO NOT USE

// MATHBACKEND 6
//		This uses gmp_int:: definition as default
// 		GMP 6.1.1 / NTL 10.3.0 backend

// MATHBACKEND 7
// 		This uses native_int:: as the default
// 		This backend provides a maximum size of 64 bits

//To select backend, please UNCOMMENT the appropriate line rather than changing the number on the
//uncommented line (and breaking the documentation of the line)

//#define MATHBACKEND 2
#define MATHBACKEND 3
//#define MATHBACKEND 4 
//#define MATHBACKEND 6 
//#define MATHBACKEND 7

// note we always want to include these

////////// cpu_int code
#include "cpu_int/binint.cpp"
#include "cpu_int/binvect.cpp"
typedef uint32_t integral_dtype;
static_assert(cpu_int::DataTypeChecker<integral_dtype>::value,"Data type provided is not supported in BigBinaryInteger");

	/** Define the mapping for BigBinaryInteger
	    1500 is the maximum bit width supported by BigBinaryIntegers, large enough for most use cases
		The bitwidth can be decreased to the least value still supporting BBI multiplications for a specific application -
		to achieve smaller runtimes
	**/
#define BigBinaryIntegerBitLength 1500 //for documentation on tests

namespace cpu_int {
typedef BigBinaryInteger<integral_dtype,BigBinaryIntegerBitLength> BinaryInteger;
typedef BigBinaryVectorImpl<BinaryInteger> BinaryVector;
}

////////// for exp_int, decide if you want 32 bit or 64 bit underlying integers in the implementation
#if MATHBACKEND == 2 || MATHBACKEND == 3 || MATHBACKEND == 5 || MATHBACKEND == 7
#define UBINT_32
#define MATH_UBBITS	32
typedef uint32_t expdtype;
#else
#define UBINT_64
#define MATH_UBBITS	64
typedef uint64_t expdtype;
#endif
#include "exp_int/ubint.h" //experimental dbc unsigned big integers or ubints
#include "exp_int/ubintvec.h" //vectors of experimental ubints
#include "exp_int/mubintvec.h" //rings of ubints

namespace exp_int {
/** Define the mapping for ExpBigBinaryInteger (experimental) */
typedef ubint<expdtype> xubint;

/** Define the mapping for Big Integer Vector */
typedef ubintvec<xubint> xubintvec;

/** Define the mapping for modulo Big Integer Vector */
typedef mubintvec<xubint> xmubintvec;
}

////////// for gmp int
#include "gmp_int/gmpint.h" //experimental gmp unsigned big ints
#include "gmp_int/mgmpint.h" //experimental gmp modulo unsigned big ints
#include "gmp_int/gmpintvec.h" //vectors of such
#include "gmp_int/mgmpintvec.h" //rings of such

////////// for native int
#include "native_int/binint.h"
#include <initializer_list>
#define MATH_NATIVEBITS	64

namespace native_int {
typedef NativeInteger<uint64_t> BigBinaryInteger;
typedef cpu_int::BigBinaryVectorImpl<NativeInteger<uint64_t>> BigBinaryVector;
}

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#if MATHBACKEND == 2

	typedef cpu_int::BinaryInteger BigBinaryInteger;
	typedef cpu_int::BinaryVector BigBinaryVector;
	
#define MATH_DEFBITS BigBinaryIntegerBitLength

#endif

#if MATHBACKEND == 3 || MATHBACKEND == 4

	typedef exp_int::xubint BigBinaryInteger;
	typedef exp_int::xmubintvec BigBinaryVector;

#define MATH_DEFBITS 0

#endif


#if MATHBACKEND == 6

	/** Define the mapping for BigBinaryInteger */
	typedef NTL::myZZ BigBinaryInteger;
	
	/** Define the mapping for BigBinaryVector */
    typedef NTL::myVecP<NTL::myZZ_p> BigBinaryVector;

// 	/** Define the mapping for ubint */
//	typedef NTL::myZZ ubint;
//
//	/** Define the mapping for modulo ubint */
//	//typedef gmp_int::myZZ ubint;
//	typedef NTL::myZZ_p mubint;
//
//	/** Define the mapping for ubint Vector */
//	typedef NTL::myVec<NTL::myZZ> ubintvec;
//
//	/** Define the mapping for modulo ubint Vector */
//	typedef NTL::myVecP<NTL::myZZ_p> mubintvec;

#define MATH_DEFBITS 0

#endif

#if MATHBACKEND == 7

	typedef native_int::BigBinaryInteger BigBinaryInteger;
	typedef native_int::BigBinaryVector BigBinaryVector;

#define MATH_DEFBITS MATH_NATIVEBITS
#endif

	template<typename IntType> class ILParamsImpl;
	template<typename ModType, typename IntType, typename VecType, typename ParmType> class ILVectorImpl;

	typedef ILParamsImpl<BigBinaryInteger> ILParams;
	typedef ILVectorImpl<BigBinaryInteger, BigBinaryInteger, BigBinaryVector, ILParams> ILVector2n;

	typedef ILParamsImpl<native_int::BigBinaryInteger> ILNativeParams;
	typedef ILVectorImpl<native_int::BigBinaryInteger, native_int::BigBinaryInteger, native_int::BigBinaryVector, ILNativeParams> ILVectorNative2n;

} // namespace lbcrypto ends

#endif
