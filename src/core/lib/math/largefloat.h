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
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This file contains the functionality to switch between rational math library backends
 */

#ifndef LBCRYPTO_LARGE_FLOAT_BACKEND_H
#define LBCRYPTO_LARGE_FLOAT_BACKEND_H

 /*! Define the library being used.  Use 1 to represent large floats.*/
#define LARGEFLOATBACKEND 1  // 1 for boost floating point, and so on

#if LARGEFLOATBACKEND == 1

	//#include <boost/math/constants/constants.hpp>
#include <boost/multiprecision/gmp.hpp>
#endif

#include <random>
//#include <boost/multiprecision/random.hpp>
#include <boost/random.hpp>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#if LARGEFLOATBACKEND == 1

	//defined for floats with 50 significant decimal digits; can be increased to 100 if needed
	using boost::multiprecision::mpf_float_30;

	/** Define the mapping for type large float */
#if defined(_MSC_VER)
	typedef boost::multiprecision::mpf_float_30 LargeFloat;
#else
	typedef boost::multiprecision::mpf_float_30 LargeFloat;
#endif
#endif

} // namespace lbcrypto ends

#endif
