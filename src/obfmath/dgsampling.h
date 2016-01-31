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
Contributors:
Daniele Micciancio (UCSD), daniele@cs.ucsd.edu
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

#include "largefloat.h"
#include "randomizedround.h"
//#include "matrix.h"

namespace lbcrypto {

	// forward declaration as it is defined after a call to it is made
	void ContinuousGaussianGenerator(ILMat<LargeFloat> *randomVector);

	/**
	* Nonspherical sampling that is used to generate perturbation vectors (for spherically distributed premimages in GaussSample)
	*
	* @param sigmaP covariance matrix of dimension (2+k)n * (2+k)n.
	* @param stddev standard deviation.
	* @param *perturbationVector perturbation vector (2+k)n
	*/
	inline void NonSphericalSample(size_t n, const BigBinaryInteger& modulus, const ILMat<int32_t> &sigmaP, double stddev, ILMat<int32_t> *perturbationVector)
	{
		int32_t a(floor(stddev/2));

		// YSP added the a^2*I term which was missing in the original LaTex document
		ILMat<int32_t> sigmaA = sigmaP - (a*a)*ILMat<int32_t>(sigmaP.GetAllocator(), sigmaP.GetRows(), sigmaP.GetCols()).Identity();

		ILMat<LargeFloat> sigmaSqrt = Cholesky(sigmaA);

		ILMat<LargeFloat> sample([](){ return make_unique<LargeFloat>(); }, sigmaSqrt.GetRows(), 1);

		ContinuousGaussianGenerator(&sample);

		ILMat<LargeFloat> p = sigmaSqrt.Mult(sample);
		RandomizeRound(n, p,a,perturbationVector);

	}

	/**
	* Generates a vector using continuous Guassian distribution with mean = 0 and std = 1; uses Box-Muller method
	*
	* @param size vector length
	* @param *vector where results are written
	*/
	inline void ContinuousGaussianGenerator(ILMat<LargeFloat> *randomVector)
	{

		namespace mp = boost::multiprecision;

		// YSP we use Box-Muller method for generating continuous gaussians included with Boost
		// please note that <> is used; boost::random::normal_distribution<LargeFloat> was causing a compilation error in Linux
		boost::random::normal_distribution<> dgg(0.0, 1.0);

		// gen is a static variable (defined in this file only through #include to largefloat.h)
		for (size_t i = 0; i < randomVector->GetRows(); i++) {
			(*randomVector)(i,0) = dgg(gen);
		}
	}

	/**
	* Gaussian sampling from lattice for gagdet matrix G and syndrome u
	*
	* @param u syndrome (a polynomial)
	* @param sttdev standard deviation
	* @param k number of components in the gadget vector
	* @param dgg discrete Gaussian generator
	* @param *z a set of k sampled polynomials corresponding to the gadget matrix G; represented as Z^(k x n)
	*/
	inline void GaussSampG(const ILVector2n &u, double sttdev, size_t k,
		DiscreteGaussianGenerator &dgg, ILMat<BigBinaryInteger> *z)
	{
        const BigBinaryInteger& modulus = u.GetParams().GetModulus();
		for (size_t i = 0; i < u.GetLength(); i++) {

			//initial value of integer syndrome corresponding to component u_i
			BigBinaryInteger t(u.GetValAtIndex(i));

			for (size_t j = 0; j < k; j++) {

				//get the least significant digit of t; used for choosing the right coset to sample from 2Z or 2Z+1
				uint32_t lsb = t.GetDigitAtIndexForBase(1,2);

				//dgLSB keeps track of the least significant bit of discrete gaussian; initialized to 2 to make sure the loop is entered
				uint32_t dgLSB = 2;
				BigBinaryInteger sampleInteger;

				//checks if the least significant bit of t matches the least signficant bit of a discrete Gaussian sample
				while(dgLSB != lsb)
				{
					sampleInteger = dgg.GenerateInteger(modulus);
					dgLSB = sampleInteger.GetDigitAtIndexForBase(1,2);
				}

				(*z)(j,i) = sampleInteger;

				//division by 2
				// TODO: Probably incorrect, but this whole function is wrong anyways. Awaiting advice of Daniele
                t = (t.ModSub((*z)(j,i), modulus))>>1;
                //t = (t - (*z)(j,i))>>1;

			}

		}

	}
	/**
	* Gaussian sampling from lattice for gagdet matrix G and syndrome u and arbitrary modulus q
	*
	* @param u syndrome (a polynomial)
	* @param sttdev standard deviation
	* @param k number of components in the gadget vector
	* @param q integer modulus 
	* @param dgg discrete Gaussian generator
	* @param *z a set of k sampled polynomials corresponding to the gadget matrix G; represented as Z^(k x n)
	*/
	inline void GaussSampGq(const ILVector2n &u, double stddev, size_t k, const BigBinaryInteger &q,
				DiscreteGaussianGenerator &dgg, ILMat<BigBinaryInteger> *z)
	{
	  std::vector<double> a(k);  /* can be precomputed, depends only on k */ 
	  std::vector<double> x(k);  /* not essential, used only for clarity */
	  std::vector<double> c(k);  /* not essential, used only for clarity */
	  std::vector<BigBinaryInteger> d(k);  /* not essential, used only for clarity */
	  std::vector<double> y(k);

	  double std3 = stddev/3;
	  std::normal_distribution<double> dggstd3(0.0, std3);

	  double stdk = std3 * (pow(2,k)/q.ConvertToDouble());

	  a[0] = sqrt(3 + 2.0/k);
	  for (size_t i=1; i<k; i++) 
	    a[i] = sqrt(2+2.0/(k-i));
	
	  for (size_t i = 0; i < u.GetLength(); i++) {

	    BigBinaryInteger v(u.GetValAtIndex(i));
	    BigBinaryInteger zk,zj;

	    for (size_t i=0; i<k; i++)
	      x[i] = dggstd3(gen);

	    y[0] = a[0]*x[0]/2 + x[1]/a[1];
	    for (size_t j=1; j<k-2; j++)
	      y[j] = y[j-1]/2 +  a[j] * x[j] /2 + x[j+1]/a[j+1];
	    y[k-1] = y[k-2]/2 + a[k-1]*x[k-1]/2;
	      
	    zk = dgg.GenerateInteger((pow(2,k) / q.ConvertToDouble())*y[k-1] - (v.ConvertToDouble() / q.ConvertToDouble()), stdk, u.GetLength(),u.GetModulus()); /* FIX: compute (2^k / q) and  v/q as doubles */;

	    for (size_t j=0; i<k-1; i++) {
	      d[j] = UintToBigBinaryInteger(v.GetDigitAtIndexForBase(j+1,2)) + zk*UintToBigBinaryInteger(q.GetDigitAtIndexForBase(j+1,2));
	      /* How efficient is GetDigitIndexForBase? Implement using left shifts? */
	      (*z)(j,i) = d[j];
	    }
	    c[0] = d[0].ConvertToDouble() / 2.0;

	    for (size_t j=0; i<k-2; i++) {
	      c[j+1] = (c[j] + d[i+1].ConvertToDouble()) / 2;
	      zj = dgg.GenerateInteger(y[j] - c[j], std3, u.GetLength(),u.GetModulus()); /* generate discrete gaussian sample with mean y[j]-c[j] and standard deviation std3 */
	      (*z)(j,i) += zj<<1; //multiplication by 2
	      (*z)(j+1,i) -= zj;
	    }
	  }
	  
	}

}

#endif