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

//#include <boost/multiprecision/random.hpp>
//#include <boost/random.hpp>
//#include <boost/multiprecision/cpp_int.hpp>
//#include <boost/multiprecision/number.hpp>

#include "largefloat.h"
#include "randomizedround.h"
#include "matrix.h"

namespace lbcrypto {
		
	//static unsigned s = std::random_device()(); // Set seed from random_device
	//static std::mt19937 gen(s);                   // Initialize URNG

	void ContinuousGaussianGenerator(ILMat<LargeFloat> *randomVector);

	/**
	* Nonspherical sampling that is used to generate perturbation vectors (for spherically distributed premimages in GaussSample)
	*
	* @param sigmaP covariance matrix of dimension (2+k)n * (2+k)n.
	* @param stddev standard deviation.
	* @param *perturbationVector perturbation vector (2+k)n
	*/
	void NonSphericalSample(const ILMat<int32_t> &sigmaP, double stddev, ILMat<int32_t> *perturbationVector) 
	{
		int32_t a(floor(stddev/2));
		size_t n = sigmaP.GetRows();
		
		ILMat<int32_t> sigmaA = sigmaP - a*ILMat<int32_t>([](){ return make_unique<int32_t>(); }, n, n).Identity();
		
		ILMat<LargeFloat> sigmaSqrt = Cholesky(sigmaA);

		ILMat<LargeFloat> sample([](){ return make_unique<LargeFloat>(); }, n, 1);
			
		ContinuousGaussianGenerator(&sample);

		ILMat<LargeFloat> p = sigmaSqrt.Mult(sample);

		RandomizeRound(p,a,perturbationVector);

	}

	/**
	* Generates a vector using continuous Guassian distribution with mean = 0 and std = 1; uses Box-Muller method
	*
	* @param size vector length
	* @param *vector where results are written
	*/
	void ContinuousGaussianGenerator(ILMat<LargeFloat> *randomVector) 
	{

		namespace mp = boost::multiprecision;

		//unsigned s = std::random_device()(); // Set seed from random_device
		//std::mt19937 gen(s);                   // Initialize URNG

		boost::random::normal_distribution<> dgg(0.0, 1.0);

		//boost::random::independent_bits_engine<boost::mt19937, 50L * 1000L / 301L, mp::number<mp::cpp_int::backend_type, mp::et_off> > gen1;

		for (size_t i = 0; i < randomVector->GetRows(); i++) {
			//std::cout<<dgg(gen)<<std::endl;
			(*randomVector)(i,0) = dgg(gen);
		}	
	}
}

#endif
