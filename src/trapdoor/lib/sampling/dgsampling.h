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

#include "math/matrix.h"
#include "lattice/field2n.h"

namespace lbcrypto {

//Statistical error in Gaussian sampling
//corresponds to statistical error of 2^(-80)
const double DG_ERROR = 8.27181e-25;

//Maximum ring dimension to be supported - up to 560 bits in the modulus
const int32_t N_MAX = 16384;

//Smoothing parameter also used as a "standard deviation" for generating error polynomials
const double SIGMA = std::sqrt(std::log(2 * N_MAX / DG_ERROR) / M_PI);

//const double SPECTRAL_CONSTANT = 1.2;
const double SPECTRAL_CONSTANT = 1.80;

const auto SPECTRAL_BOUND = [](uint32_t n, uint32_t k) -> double { 
	return SPECTRAL_CONSTANT*SIGMA*SIGMA*(std::sqrt(n*k) + std::sqrt(2*n) + 4.7); 
};

/**
* @brief Utility class containing operations needed for lattice sampling; Sources: https://eprint.iacr.org/2013/297.pdf & https://eprint.iacr.org/2011/501.pdf
* This construction is based on the hardness of Ring-LWE problem 
*/
class LatticeGaussSampUtility
{
public:

	/**
	* Gaussian sampling from lattice for gagdet matrix G and syndrome u ONLY FOR A POWER-OF-TWO MODULUS; Has not been fully tested
	*
	* @param u syndrome (a polynomial)
	* @param sttdev standard deviation
	* @param k number of components in the gadget vector
	* @param dgg discrete Gaussian generator
	* @param *z a set of k sampled polynomials corresponding to the gadget matrix G; represented as Z^(k x n)
	*/
	static inline void GaussSampG(const Poly &u, double sttdev, size_t k,
			Poly::DggType &dgg, Matrix<BigInteger> *z);

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
	static inline void GaussSampGq(const Poly &u, double stddev, size_t k, const BigInteger &q, int32_t base, 
				Poly::DggType &dgg, Matrix<int32_t> *z);


	/**
	* Subroutine used by ZSampleSigmaP
	*
	* @param a field element in DFT format
	* @param b field element in DFT format
	* @param d field element in DFT format
	* @param c a vector of field elements in Coefficient format
	* @param dgg discrete Gaussian generator
	* @param *p non-spherical perturbation vector; output of the function
	*/
	static inline void ZSampleSigma2x2(const Field2n & a, const Field2n & b,
		const Field2n & d, const Matrix<Field2n> &c, const Poly::DggType & dgg, Matrix<int32_t>* p);

	/**
	* Subroutine used by ZSampleSigma2x2
	*
	* @param f field element in Coefficient format
	* @param c field element in Coefficient format
	* @param dgg discrete Gaussian generator
	* @param n ring dimension used for rejection sampling
	*/
	static inline Matrix<int32_t> ZSampleF(const Field2n &f, const Field2n &c,
		const Poly::DggType &dgg, size_t n);

private:
	
	// subroutine used by GaussSampGqV2
	// Algorithm was provided in a personal communication by Daniele Micciancio
	static inline void Perturb(double sigma,  size_t k, size_t n, 
		const vector<double> &l, const vector<double> &h, int32_t base, Poly::DggType &dgg, vector<int32_t> *p);

	// subroutine used by GaussSampGqV2
	// Algorithm was provided in a personal communication by Daniele Micciancio
	static inline void SampleC(const Matrix<double> &c, size_t k, size_t n, 
		double sigma, Poly::DggType &dgg, Matrix<double> *a, vector<int32_t> *z);

	//subroutine used by ZSampleF
	//Algorithm utilizes the same permutation algorithm discussed in the GM17 paper
	  static inline Matrix<int32_t> Permute(Matrix<int32_t> * p);

};

}

#endif
