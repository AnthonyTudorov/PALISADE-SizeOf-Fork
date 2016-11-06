/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: 
*		Dr. Yuriy Polyakov, <polyakov@njit.edu>
*		Kevin King, kcking@mit.edu
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2016, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
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
* This code provides the utility for lattice Gaussian sampling (needed by lattice trapdoors).
*/


#ifndef LBCRYPTO_OBFMATH_DGSAMPLING_H
#define LBCRYPTO_OBFMATH_DGSAMPLING_H

#include "../math/largefloat.h"
#include "../math/matrix.h"

namespace lbcrypto {

/**
* @brief Utility class containing operations needed for lattice sampling; Sources: https://eprint.iacr.org/2013/297.pdf & https://eprint.iacr.org/2011/501.pdf
* This construction is based on the hardness of Ring-LWE problem 
*/
class LatticeGaussSampUtility
{
public:
	/**
	* Nonspherical sampling that is used to generate perturbation vectors (for spherically distributed premimages in GaussSample)
	*
	* @param sigmaP covariance matrix of dimension (2+k)n * (2+k)n.
	* @param stddev standard deviation.
	* @param *perturbationVector perturbation vector (2+k)n
	*/
	static inline void NonSphericalSample(size_t n, const Matrix<LargeFloat> &sigmaSqrt, double stddev, Matrix<int32_t> *perturbationVector);

	/**
	* Generates a vector using continuous Guassian distribution with mean = 0 and std = 1; uses Box-Muller method
	*
	* @param size vector length
	* @param *vector where results are written
	*/
	static inline void ContinuousGaussianGenerator(Matrix<LargeFloat> *randomVector);

	/**
	* Gaussian sampling from lattice for gagdet matrix G and syndrome u ONLY FOR A POWER-OF-TWO MODULUS; Has not been fully tested
	*
	* @param u syndrome (a polynomial)
	* @param sttdev standard deviation
	* @param k number of components in the gadget vector
	* @param dgg discrete Gaussian generator
	* @param *z a set of k sampled polynomials corresponding to the gadget matrix G; represented as Z^(k x n)
	*/
	static inline void GaussSampG(const ILVector2n &u, double sttdev, size_t k,
		DiscreteGaussianGenerator &dgg, Matrix<BigBinaryInteger> *z);

	/**
	* Gaussian sampling from lattice for gagdet matrix G and syndrome u and ARBITRARY MODULUS q
	* Algorithm was provided in a personal communication by Daniele Micciancio
	*
	* @param u syndrome (a polynomial)
	* @param sttdev standard deviation
	* @param k number of components in the gadget vector
	* @param q integer modulus
	* @param dgg discrete Gaussian generator
	* @param *z a set of k sampled polynomials corresponding to the gadget matrix G; represented as Z^(k x n)
	*/
	static inline void GaussSampGq(const ILVector2n &u, double stddev, size_t k, const BigBinaryInteger &q,
				DiscreteGaussianGenerator &dgg, Matrix<int32_t> *z);

	/**
	* Gaussian sampling from lattice for gagdet matrix G and syndrome u and ARBITRARY MODULUS q - Improved algorithm
	* Algorithm was provided in a personal communication by Daniele Micciancio
	*
	* @param u syndrome (a polynomial)
	* @param sttdev standard deviation
	* @param k number of components in the gadget vector
	* @param q integer modulus
	* @param dgg discrete Gaussian generator
	* @param *z a set of k sampled polynomials corresponding to the gadget matrix G; represented as Z^(k x n)
	*/
	static inline void GaussSampGqV2(const ILVector2n &u, double stddev, size_t k, const BigBinaryInteger &q, int32_t base, 
				DiscreteGaussianGenerator &dgg, Matrix<int32_t> *z);

	/**
	* Randomized rounding according to Section 4.3 of https://eprint.iacr.org/2013/297.pdf and 
	* Section 4.1 of https://web.eecs.umich.edu/~cpeikert/pubs/pargauss.pdf
	*
	* @param n ring dimension
	* @param &p rational Gaussian sample
	* @param &sigma distribution parameter
	* @param *perturbationVector non-spherical perturbation vector; output of the function
	*/
	static inline void RandomizeRound(size_t n, const Matrix<LargeFloat> &p, const LargeFloat &sigma, Matrix<int32_t> *perturbationVector) {
		for (size_t i = 0; i < p.GetRows(); i++) {
			(*perturbationVector)(i,0) = DiscreteGaussianGenerator::GenerateInteger(p(i,0), sigma, n);
		}
	};
	void ZSampleSigmaP(size_t n, BigBinaryInteger q, double s, double sigma, Matrix<ILVector2n> Tprime, Matrix<int32_t> *perturbationVector);


private:
	
	// subroutine used by GaussSampGqV2
	// Algorithm was provided in a personal communication by Daniele Micciancio
	static inline void Perturb(double sigma,  size_t k, size_t n, 
		const vector<double> &l, const vector<double> &h, int32_t base, DiscreteGaussianGenerator &dgg, vector<int32_t> *p);

	// subroutine used by GaussSampGqV2
	// Algorithm was provided in a personal communication by Daniele Micciancio
	static inline void SampleC(const Matrix<double> &c, size_t k, size_t n, 
		double sigma, DiscreteGaussianGenerator &dgg, Matrix<double> *a, vector<int32_t> *z);
	
	void ZSampleSigma2x2(const std::vector<double> & a, const std::vector<double> & b, const std::vector<double> & d, const std::vector<double> & c, Matrix<int32_t>* p1);
};

}

#endif
