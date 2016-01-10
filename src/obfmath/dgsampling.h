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

#ifndef LBCRYPTO_OBFMATH_DGSAMPLING_H
#define LBCRYPTO_OBFMATH_DGSAMPLING_H

#include "randomizedround.h"
#include "matrix.h"

namespace lbcrypto {

	/**
	* Nonspherical sampling that is used to generate perturbation vectors (for spherically distributed premimages in GaussSample)
	*
	* @param sigmaP covariance matrix of dimension (2+k)n * (2+k)n.
	* @param stddev standard deviation.
	* @param *perturbationVector perturbation vector (2+k)n
	*/
	void NonSphericalSample(const ILMat<BigBinaryInteger> &sigmaP, double stddev, ILMat<BigBinaryInteger> *perturbationVector) 
	{
		BigBinaryInteger a(floor(stddev/2));
		size_t n = sigmaP.GetRows();
		
		ILMat<BigBinaryInteger>sigmaA = sigmaP - a*ILMat<BigBinaryInteger>(BigBinaryInteger::Allocator, n, n).Identity();
		ILMat<BigBinaryInteger>sigmaSqrt = sigmaA.Cholesky();


	}

}

#endif
