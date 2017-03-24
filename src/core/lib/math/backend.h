/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Jerry Ryan <gwryan@njit.edu>
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
 
/*! Define the library being used via the MATHBACKEND macro. */

// Selecting a math backend means defining which underlying implementation
// is the default BigBinaryInteger and BigBinaryVector

// It's possible (perhaps even desirable) to have multiple backends
// available at once

// MATH BACKEND 2
// Uses cpu_int definition as defaults
// Also provides exp_int backend with underlying element size of 32 bits
// 	this allows side by side comparison of cpu_int and exp_int math backend

// MATH BACKEND 3
// Uses exp_int definition with uint32_t underlying size as defaults
// new dynamicly allocated backend and support uint32_t and uint64_t on linux
// This backend supports arbitrary bitwidths; no memory pool is used; can grow up to RAM
// limitation

// MATH BACKEND 4
// Uses exp_int definition with uint64_t underlying size as defaults

// MATH BACKEND 7
// uses native64 as the default
// This backend provides a maximum size of 64 bits
// This backend ALSO enables exp_int with uint64_t

//Please UNCOMMENT the approproate line rather than changing the number on the 
//uncommented line (and breaking the documentation of the line)

//32 bit should work with all OS
#define MATHBACKEND 2 

//dynamicly allocated backend and support uint32_t and uint64_t on linux
//#define MATHBACKEND 3 

//64 bit (currently works for ubuntu, not tested otherwise
//NOTE currently MATHBACKEND 4 has issues with the following unit tests
//stemming from poor run time performance of 128 bit intrinsic divide
//UTSHE.keyswitch_ModReduce_DCRT takes incredibly rediculously long (9637 sec)
//UTSHEAdvanced.test_eval_mult_double_crt takes extremely long (89 sec)
//UTSHEAdvanced.test_eval_add_double_crt takes extremely long (86 sec)
//#define MATHBACKEND 4 

// native64 native
// #define MATHBACKEND 7	

// note we always want to include these
#include "cpu_int/binint.cpp"
#include "cpu_int/binvect.cpp"
#include "native64/binint.h"
#include <initializer_list>

namespace native64 {
typedef NativeInteger<uint64_t> BigBinaryInteger;
typedef cpu_int::BigBinaryVectorImpl<NativeInteger<uint64_t>> BigBinaryVector;
}

#if MATHBACKEND == 2

#define UBINT_32
#include "exp_int/ubint.cpp" //experimental dbc unsigned big integers or ubints
#include "exp_int/ubintvec.cpp" //vectors of experimental ubints
#include "exp_int/mubintvec.cpp" //rings of ubints

#endif

#if MATHBACKEND == 3

#define UBINT_32
#include "exp_int/ubint.cpp" //experimental dbc unsigned big integers or ubints
#include "exp_int/ubintvec.cpp" //vectors of experimental ubints
#include "exp_int/mubintvec.cpp" //rings of ubints
#endif

#if MATHBACKEND == 4

#define UBINT_64
#include "exp_int/ubint.cpp" //experimental dbc unsigned big integers or ubints
#include "exp_int/ubintvec.cpp" //vectors of experimental ubints
#include "exp_int/mubintvec.cpp" //rings of ubints

#endif

#if MATHBACKEND == 7

#define UBINT_64
#include "exp_int/ubint.cpp" //experimental dbc unsigned big integers or ubints
#include "exp_int/ubintvec.cpp" //vectors of experimental ubints
#include "exp_int/mubintvec.cpp" //rings of ubints

#endif

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

template<typename IntType> class ILParamsImpl;
template<typename IntType, typename VecType, typename ParmType> class ILVectorImpl;

#if MATHBACKEND == 2
	/** integral_dtype specifies the native data type used for the BigBinaryInteger implementation 
	    should be uint32_t for most applications **/
	typedef uint32_t integral_dtype;
	typedef uint32_t integral_dtype2;

	/** makes sure that only supported data type is supplied **/
	static_assert(cpu_int::DataTypeChecker<integral_dtype>::value,"Data type provided is not supported in BigBinaryInteger");

	/** Define the mapping for BigBinaryInteger
	    1500 is the maximum bit width supported by BigBinaryIntegers, large enough for most use cases
		The bitwidth can be decreased to the least value still supporting BBI multiplications for a specific application - to achieve smaller runtimes**/

        #define BigBinaryIntegerBitLength 1500 //for documentation on tests
	typedef cpu_int::BigBinaryInteger<integral_dtype,BigBinaryIntegerBitLength> BigBinaryInteger;

	
	/** Define the mapping for BigBinaryVector */
	typedef cpu_int::BigBinaryVectorImpl<BigBinaryInteger> BigBinaryVector;
	
	/** Define the mapping for BigBinaryMatrix */
	//typedef cpu8bit::BigBinaryMatrix BigBinaryMatrix;

	/** Define the mapping for ExpBigBinaryInteger (experimental) */
	typedef exp_int::ubint<integral_dtype2> ubint;

	/** Define the mapping for Big Integer Vector */
	typedef exp_int::ubintvec<ubint> ubintvec;

	/** Define the mapping for modulo Big Integer Vector */
	typedef exp_int::mubintvec<ubint> mubintvec;

#endif

#if MATHBACKEND == 3

	/** integral_dtype specifies the native data type used for the
	    BigBinaryInteger implementation should be uint32_t for
	    most applications **/
	typedef uint32_t integral_dtype;

	#define BigBinaryIntegerBitLength 0 // zero indicates unused

	/** Define the mapping for ExpBigBinaryInteger (experimental) */
	typedef exp_int::ubint<integral_dtype> ubint;

	/** Define the mapping for ExpBigBinaryInteger (experimental) */
	typedef exp_int::ubint<integral_dtype> BigBinaryInteger;

	/** Define the mapping for modulo Big Integer Vector */
	typedef exp_int::mubintvec<ubint> BigBinaryVector;

	/** Define the mapping for Big Integer Vector */
	typedef exp_int::ubintvec<ubint> ubintvec;

	/** Define the mapping for modulo Big Integer Vector */
	typedef exp_int::mubintvec<ubint> mubintvec;

#endif

#if MATHBACKEND == 4

	/** integral_dtype specifies the native data type used for the
	    BigBinaryInteger implementation set to uint64_t for
	    machines tha support it. */

	typedef uint64_t integral_dtype;

	#define BigBinaryIntegerBitLength 0 // zero indicates unused

	/** Define the mapping for ExpBigBinaryInteger (experimental) */
	typedef exp_int::ubint<integral_dtype> BigBinaryInteger;

	/** Define the mapping for ExpBigBinaryInteger (experimental) */
	typedef exp_int::ubint<integral_dtype> ubint;

	/** Define the mapping for modulo Big Integer Vector */
	typedef exp_int::mubintvec<ubint> BigBinaryVector;

	/** Define the mapping for Big Integer Vector */
	typedef exp_int::ubintvec<ubint> ubintvec;

	/** Define the mapping for modulo Big Integer Vector */
	typedef exp_int::mubintvec<ubint> mubintvec;

#endif

#if MATHBACKEND == 7

	typedef uint32_t integral_dtype;
	typedef uint32_t integral_dtype2;

	#define BigBinaryIntegerBitLength 0 // zero indicates unused

	typedef native64::NativeInteger<uint64_t> BigBinaryInteger;
	typedef cpu_int::BigBinaryVectorImpl<BigBinaryInteger> BigBinaryVector;

	/** Define the mapping for ExpBigBinaryInteger (experimental) */
	typedef exp_int::ubint<integral_dtype> ubint;

	/** Define the mapping for Big Integer Vector */
	typedef exp_int::ubintvec<ubint> ubintvec;

	/** Define the mapping for modulo Big Integer Vector */
	typedef exp_int::mubintvec<ubint> mubintvec;

#endif

	typedef ILParamsImpl<BigBinaryInteger> ILParams;
	typedef ILVectorImpl<BigBinaryInteger, BigBinaryVector, ILParams> ILVector2n;

	typedef ILParamsImpl<native64::BigBinaryInteger> ILNativeParams;
	typedef ILVectorImpl<native64::BigBinaryInteger, native64::BigBinaryVector, ILNativeParams> ILVectorNative2n;


} // namespace lbcrypto ends

#endif