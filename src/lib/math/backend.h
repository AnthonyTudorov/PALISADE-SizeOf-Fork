/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
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
// 1 - old implementation based on 8-bit character arrays (bytes),
// uses a memory pool for storing character arrays
// 2 - main math backend supporting arbitrary bitwidths; no memory
// pool is used; can grow up to RAM limit currently supports uint8_t,
// uint16_t, and uint32_t; uint32_t is recommended for 32- and 64-bit
// CPU architectures

#define MATHBACKEND 2

#if MATHBACKEND == 1
	#include "cpu8bit/binint.h"
	#include "cpu8bit/binvect.h"
	//#include "cpu8bit/binmat.h"	
#endif
#if MATHBACKEND == 2
	#include "cpu_int/binint.cpp"
	#include "cpu_int/binvect.cpp"	
#include "exp_int32/bint.cpp" //experimental dbc big integers
#include "exp_int32/bintvec.cpp" //vectors of experimental
//#include "exp_int32/mbint.cpp"
//	#include "exp_int32/mbintvec.cpp"

#endif
/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#if MATHBACKEND == 1
	/** Define the mapping for BigBinaryInteger */
	typedef cpu8bit::BigBinaryInteger BigBinaryInteger;
	/** Define the mapping for BigBinaryVector */
	typedef cpu8bit::BigBinaryVector BigBinaryVector;
	/** Define the mapping for BigBinaryMatrix */
	//typedef cpu8bit::BigBinaryMatrix BigBinaryMatrix;
#endif

#if MATHBACKEND == 2
	/** integral_dtype specifies the native data type used for the BigBinaryInteger implementation 
	    should be uint32_t for most applications **/
	typedef uint32_t integral_dtype;

	/** makes sure that only supported data type is supplied **/
	static_assert(cpu_int::DataTypeChecker<integral_dtype>::value,"Data type provided is not supported in BigBinaryInteger");

	/** Define the mapping for BigBinaryInteger
	    1500 is the maximum bitwidth supported by BigBinaryIntegers, large enough for most use cases
		The bitwidth can be decreased to the least value still supporting BBI multiplications for a specific application - to achieve smaller runtimes**/
	typedef cpu_int::BigBinaryInteger<integral_dtype,1500> BigBinaryInteger;
	
	/** Define the mapping for BigBinaryVector */
	typedef cpu_int::BigBinaryVector<BigBinaryInteger> BigBinaryVector;
	
	/** Define the mapping for BigBinaryMatrix */
	//typedef cpu8bit::BigBinaryMatrix BigBinaryMatrix;

	/** Define the mapping for ExpBigBinaryInteger (experimentaa)
	    1500 is the maximum bitwidth supported by BigBinaryIntegers, large enough for most use cases
		The bitwidth can be decreased to the least value still supporting BBI multiplications for a specific application - to achieve smaller runtimes**/
	typedef exp_int32::bint<integral_dtype,1500> bint;

	/** Define the mapping for Big Integer Vector */
	typedef exp_int32::bintvec<bint> bintvec;

#endif

} // namespace lbcrypto ends

#endif
