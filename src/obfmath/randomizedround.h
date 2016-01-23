// LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
6/1/2015 5:37AM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Kevin King, kcking@mit.edu
Description:
This code provides basic lattice ideal manipulation functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef LBCRYPTO_MATHOBF_RANDOMIZED_ROUND_H
#define LBCRYPTO_MATHOBF_RANDOMIZED_ROUND_H

#include <random>
using std::uniform_int_distribution;

#define _USE_MATH_DEFINES // added for Visual Studio support
#include <math.h>
#include <boost/multiprecision/random.hpp>
#include <boost/random.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include "../utils/inttypes.h"
#include "largefloat.h"
#include "matrix.h"

namespace lbcrypto {

	//static variables used for initializing continuous and discrete distributions
	static std::random_device rd;
	static unsigned s = std::random_device()(); // Set seed from random_device
	static std::mt19937 gen(s);                   // Initialize URNG

	//
	// All rational computations use boost floating point typedefed in largefloat.h
	//

	inline LargeFloat UnnormalizedGaussianPDF(const LargeFloat &mean, const LargeFloat &sigma, int32_t x) {
		return pow(M_E, -pow(x - mean, 2)/(2. * sigma * sigma));
	}

	/**
	 *  int32_t is used here as the components are relatively small
	 */
	inline int32_t IntegerRejectionSample(const LargeFloat &mean, const LargeFloat &stddev, size_t n) {

		LargeFloat t = log(n)/log(2);  //fix for Visual Studio

		//YSP this double conversion is necessary for uniform_int to work properly; the use of double is justified in this case
		double dbmean = mean.convert_to<double>();
		double dbt = t.convert_to<double>();

		uniform_int_distribution<int32_t> uniform_int(floor(dbmean - dbt), ceil(dbmean + dbt));
		boost::random::uniform_real_distribution<LargeFloat> uniform_real(0.0,1.0);

		while (true) {
			//  pick random int
			int32_t x = uniform_int(rd);
			//  roll the uniform dice
			LargeFloat dice = uniform_real(gen);
			//  check if dice land below pdf
			if (dice <= UnnormalizedGaussianPDF(mean, stddev, x)) {
				return x;
			}
		}
	}

	inline void RandomizeRound(size_t n, const ILMat<LargeFloat> &p, const LargeFloat &sigma, ILMat<int32_t> *perturbationVector) {

		for (size_t i = 0; i < p.GetRows(); i++) {
            const LargeFloat& decimal = p(i,0) - floor(p(i,0));
            //  TODO: FIX CONVERSION
			(*perturbationVector)(i,0) = (int32_t) floor(p(i,0)) + IntegerRejectionSample(decimal, sigma, n);
		}

	}

}

#endif
