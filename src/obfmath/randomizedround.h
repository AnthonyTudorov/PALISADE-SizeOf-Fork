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
using std::uniform_real_distribution;
//#include <math.h>

#define _USE_MATH_DEFINES // added for Visual Studio support
#include <math.h>
#include "../utils/inttypes.h"

namespace lbcrypto {

	static std::random_device rd;

	//
	//  Since we do not have a BigRational implementation, everything is computed in
	//  doubles for now.
	//

	inline double UnnormalizedGaussianPDF(double mean, double sigma, double x) {
		return pow(M_E, -pow(x - mean, 2)/(2. * sigma * sigma));
	}

	/**
	 *  @param n the ring dimension
	 */
	inline usint IntegerRejectionSample(double mean, double stddev, size_t n) {
		double t = log(n)/log(2);  //fix for Visual Studio
		uniform_int_distribution<long> uniform_int(floor(mean - t), ceil(mean + t));
		std::uniform_real_distribution<double> uniform_real(0.0, 1.0);
		while (true) {
			//  pick random int
			usint x = uniform_int(rd);
			//  roll the uniform dice
			double dice = uniform_real(rd);
			//  check if dice land below pdf
			if (dice <= UnnormalizedGaussianPDF(mean, stddev, x)) {
				return x;
			}
		}
	}

	/**
	 *  @param n the ring dimension
	 *
	 *  @return
	 */
	inline usint RandomizeRound(double x, double sigma, size_t n) {
		//  sample from gaussian over integers centered at x
		return IntegerRejectionSample(x, sigma, n);
	}

}

#endif
