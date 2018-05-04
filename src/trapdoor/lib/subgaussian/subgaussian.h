/**
 * @file subgaussian.h Provides implementation of subgaussian sampling algorithms
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#include <random>
#include "math/matrix.h"

#ifndef LBCRYPTO_LATTICE_SUBGAUSSIAN_H
#define LBCRYPTO_LATTICE_SUBGAUSSIAN_H

namespace lbcrypto {

template <class Integer, class Vector>
class LatticeSubgaussianUtility
{
public:

	LatticeSubgaussianUtility() : m_base(2), m_modulus(1), m_k(1) {};

	LatticeSubgaussianUtility(const uint32_t &base, const Integer &modulus, const uint32_t &k) :
		m_base(base), m_modulus(modulus), m_k(k) {Precompute();};

	void InverseG(const Integer &u, vector<int64_t> *output) const;

	void BcBD(const vector<float> &target, vector<int64_t> *x) const;

	const uint32_t GetK() const {return m_k;}

private:

	void Precompute();

	// input parameters
	uint32_t m_base;
	Integer m_modulus;
	uint32_t m_k;

	// precomputed tables
	vector<int64_t> m_qvec;
	vector<float> m_d;

};

void InverseRingVector(const LatticeSubgaussianUtility<BigInteger,BigVector> &util, const shared_ptr<ILParams> ilParams, const Matrix<Poly> &pubElemB, Matrix<Poly> *psi);

}

#endif
