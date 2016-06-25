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
* This code provides the utility for working with trapdoor lattices.
*/


#ifndef LBCRYPTO_LATTICE_TRAPDOOR_H
#define LBCRYPTO_LATTICE_TRAPDOOR_H

#include "../math/matrix.h"
#include "../lattice/ilvector2n.h"
#include "dgsampling.h"
#include "../utils/debug.h"

namespace lbcrypto {

typedef Matrix<ILVector2n> RingMat;

/**
* @brief Class to store a lattice trapdoor pair generated using construction 1 in section 3.2 of https://eprint.iacr.org/2013/297.pdf
* This construction is based on the hardness of Ring-LWE problem 
*/
class RLWETrapdoorPair {
public:
	// matrix of noise polynomials
	RingMat m_r;
	// matirx 
	RingMat m_e;

	RLWETrapdoorPair(const RingMat &r, const RingMat &e): m_r(r), m_e(e) {};
};

/**
* @brief Static class implementing lattice trapdoor construction 1 in section 3.2 of https://eprint.iacr.org/2013/297.pdf
*/
class RLWETrapdoorUtility
{
public:
	/**
	* Trapdoor generation method as described in section 3.2 of https://eprint.iacr.org/2013/297.pdf
	*
	* @param params ring element parameters
	* @param sttdev distribution parameter used in sampling noise polynomials of the trapdoor
	* @return the trapdoor pair including the public key (matrix of rings) and trapdoor itself
	*/
	static inline std::pair<RingMat, RLWETrapdoorPair> TrapdoorGen(ILParams params, int stddev);

	/**
	* Gaussian sampling introduced in https://eprint.iacr.org/2011/501.pdf and described 
	* in a simple manner in https://eprint.iacr.org/2013/297.pdf
	*
	* @param n ring dimension
	* @param k matrix sample dimension; k = logq + 2
	* @param &A public key of the trapdoor pair
	* @param &T trapdoor itself
	* @param &SigmaP Cholesky decomposition matrix for the trapdoor
	* @param &u syndrome vector where gaussian that Gaussian sampling is centered around
	* @param sigma noise distriubution parameter
	* @param &dgg discrete Gaussian generator for integers
	* @return the sampled vector (matrix)
	*/
	static inline RingMat GaussSamp(size_t n, size_t k, const RingMat& A, const RLWETrapdoorPair& T, 
			const Matrix<LargeFloat> &SigmaP, const ILVector2n &u,
			double sigma, DiscreteGaussianGenerator &dgg); 

	/**
	* Generation of perturbation matrix based on Cholesky decomposition 
	* see Section 3.2 of https://eprint.iacr.org/2013/297.pdf for details
	*
	* @param n ring dimension
	* @param k matrix sample dimension; k = logq + 2
	* @param &A public key of the trapdoor pair
	* @param &T trapdoor itself
	* @param s parameter s needed for Cholesky decomposition to succeed; see https://eprint.iacr.org/2011/501.pdf for more details
	* @param *sigmaSqrt Choleskry decomposition matrix - output of the function
	*/
	static inline void PerturbationMatrixGen(size_t n, size_t k, const RingMat& A, 
			const RLWETrapdoorPair& T, double s, Matrix<LargeFloat> *sigmaSqrt); 
};

} //end namespace crypto
#endif
