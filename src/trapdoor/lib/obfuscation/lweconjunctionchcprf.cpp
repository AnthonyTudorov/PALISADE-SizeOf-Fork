/**
 * @file lweconjunctionchcprf.cpp Implementation of conjunction constraint-hiding constrained PRFs as described in https://eprint.iacr.org/2017/143.pdf
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

#ifndef LBCRYPTO_OBFUSCATE_LWECONJUNCTIONCHCPRF_CPP
#define LBCRYPTO_OBFUSCATE_LWECONJUNCTIONCHCPRF_CPP

#include "lweconjunctionchcprf.h"

namespace lbcrypto {

template <class Element>
LWEConjunctionCHCPRFAlgorithm<Element>::LWEConjunctionCHCPRFAlgorithm(usint base, usint chunkSize, usint length, usint n)
	: m_base(base)
	, m_chunkSize(chunkSize)
	, m_length(length)
	, m_adjustedLength(length / chunkSize)
	, m_chunkExponent(1 << m_chunkSize)
	, m_dgg(SIGMA)
	, m_A(new std::vector<Matrix<Element>>())
	, m_T(new std::vector<RLWETrapdoorPair<Element>>()) {

	// Generate ring parameters
	double q = EstimateRingModulus(n);
	m_elemParams = GenerateElemParams(q, n);

	double modulus = m_elemParams->GetModulus().ConvertToDouble();

	// Initialize m_dggLargeSigma
	usint k = floor(log2(modulus-1.0)+1.0);
	usint m = ceil(k/log2(base)) + 2;

	double c = (base + 1) * SIGMA;
	double s = SPECTRAL_BOUND(n, m - 2, base);

	if (sqrt(s * s - c * c) <= 3e5)
		m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
	else
		m_dggLargeSigma = m_dgg;

	// Generate encoding keys
	EncodingParamsGen();

};

template <class Element>
usint LWEConjunctionCHCPRFAlgorithm<Element>::GetRingDimension() const {
	return m_elemParams->GetRingDimension();
}

template <class Element>
usint LWEConjunctionCHCPRFAlgorithm<Element>::GetLogModulus() const {
	double q = m_elemParams->GetModulus().ConvertToDouble();
	usint logModulus = floor(log2(q - 1.0) + 1.0);
	return logModulus;
}

template <class Element>
shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> LWEConjunctionCHCPRFAlgorithm<Element>::KeyGen() {

	shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> S(new vector<vector<shared_ptr<Matrix<Element>>>>());

	for (usint i = 0; i < m_adjustedLength; i++) {
		vector<shared_ptr<Matrix<Element>>> S_i;

		for (usint k = 0; k < m_chunkExponent; k++) {
			Element s_ik = Element(m_tug, m_elemParams, COEFFICIENT);
			s_ik.SwitchFormat();

			shared_ptr<Matrix<Element>> S_ik = Encode(i, i + 1, s_ik);
			S_i.push_back(S_ik);
		}

		S->push_back(S_i);
	}

	return S;
};


template <class Element>
shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> LWEConjunctionCHCPRFAlgorithm<Element>::Constrain(const shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> key, const std::string &pattern) {

	shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> S(new vector<vector<shared_ptr<Matrix<Element>>>>());

	for (usint i = 0; i < m_adjustedLength; i++) {
		// current chunk of cleartext pattern
		std::string chunk = pattern.substr(i * m_chunkSize, m_chunkSize);

		// build a chunk mask that maps "10??" to "1100" - ones correspond to non-wildcard character
		std::string chunkTemp = replaceChar(chunk, '0', '1');
		chunkTemp = replaceChar(chunkTemp, '?', '0');
		// store the mask as integer for bitwise operations
		usint chunkMask = std::stoi(chunkTemp, nullptr, 2);

		// build a chunk target that maps "10??" to "1000" - replacing wilcard character by 0
		chunkTemp = replaceChar(chunk, '?', '0');
		usint chunkTarget = std::stoi(chunkTemp, nullptr, 2);

		vector<shared_ptr<Matrix<Element>>> S_i;

		for (usint k = 0; k < m_chunkExponent; k++) {
			if ((k & chunkMask) == chunkTarget) {
				S_i.push_back((*key)[i][k]);
			}
			else {
				// Replace S_ik with fresh encoding if k does not match pattern
				Element s_ik = Element(m_tug, m_elemParams, COEFFICIENT);
				s_ik.SwitchFormat();

				shared_ptr<Matrix<Element>> S_ik = Encode(i, i + 1, s_ik);
				S_i.push_back(S_ik);
			}
		}

		S->push_back(S_i);
	}

	return S;

};


template <class Element>
std::string LWEConjunctionCHCPRFAlgorithm<Element>::Evaluate(const shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> key, const std::string &input) const {

	Matrix<Element> y = (*m_A)[0];

	for (usint i = 0; i < m_adjustedLength; i++) {
		std::string chunk = input.substr(i * m_chunkSize, m_chunkSize);
		int k = std::stoi(chunk, nullptr, 2);

		y = y * *(*key)[i][k];
	}

	const BigInteger &q = m_elemParams->GetModulus();
	std::stringstream output;

	for (size_t i = 0; i < y.GetCols(); i++) {
		Poly poly = y(0, i).CRTInterpolate();
		poly = poly.DivideAndRound(q);

		for (size_t j = 0; j < poly.GetLength(); j++) {
			output << poly.GetValAtIndex(j);
		}
	}

	return output.str();

};


template <class Element>
double LWEConjunctionCHCPRFAlgorithm<Element>::EstimateRingModulus(usint n) {

	//smoothing parameter - also standard deviation for noise Elementnomials
	double sigma = SIGMA;

	//assurance measure
	double alpha = 36;

	//empirical parameter
	double beta = 2;

	//Bound of the Gaussian error Elementnomial
	double Berr = sigma*sqrt(alpha);

	uint32_t length = m_length / m_chunkSize;
	uint32_t base = m_base;

	//Correctness constraint
	auto qCorrectness = [&](uint32_t n, uint32_t m, uint32_t k) -> double { return  16*Berr*pow(sqrt(m*n)*beta*SPECTRAL_BOUND(n,m-2,base),length);  };

	double qPrev = 1e6;
	double q = 0;
	usint k = 0;
	usint m = 0;

	//initial value
	k = floor(log2(qPrev-1.0)+1.0);
	m = ceil(k / log2(base)) + 2;
	q = qCorrectness(n, m, k);

	//get a more accurate value of q
	while (std::abs(q - qPrev) > 0.001*q) {
		qPrev = q;
		k = floor(log2(qPrev - 1.0) + 1.0);
		m = ceil(k / log2(base)) + 2;
		q = qCorrectness(n, m, k);
	}

	return q;

};


template <>
shared_ptr<typename DCRTPoly::Params> LWEConjunctionCHCPRFAlgorithm<DCRTPoly>::GenerateElemParams(double q, usint n) const {

	size_t dcrtBits = 60;
	size_t size = ceil((floor(log2(q - 1.0)) + 2.0) / (double)dcrtBits);

	vector<native_int::BigInteger> moduli(size);
	vector<native_int::BigInteger> roots(size);

	moduli[0] = FirstPrime<native_int::BigInteger>(dcrtBits, 2 * n);
	roots[0] = RootOfUnity<native_int::BigInteger>(2 * n, moduli[0]);

	for (size_t i = 1; i < size - 1; i++)
	{
		moduli[i] = NextPrime<native_int::BigInteger>(moduli[i-1], 2 * n);
		roots[i] = RootOfUnity<native_int::BigInteger>(2 * n, moduli[i]);
	}

	if (size > 1) {
		moduli[size-1] = FirstPrime<native_int::BigInteger>(dcrtBits-1, 2 * n);
		roots[size-1] = RootOfUnity<native_int::BigInteger>(2 * n, moduli[size-1]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(2 * n, moduli, roots));

	return params;

};


template <class Element>
void LWEConjunctionCHCPRFAlgorithm<Element>::EncodingParamsGen() {

	const shared_ptr<typename Element::Params> params = m_elemParams;
	usint base = m_base;
	usint stddev = m_dgg.GetStd();

	for(size_t i = 0; i<= m_adjustedLength; i++) {
		std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> trapPair = RLWETrapdoorUtility<Element>::TrapdoorGen(params, stddev, base); //TODO remove stddev

		m_A->push_back(trapPair.first);
		m_T->push_back(trapPair.second);
	}

};


template <class Element>
shared_ptr<Matrix<Element>> LWEConjunctionCHCPRFAlgorithm<Element>::Encode(usint i, usint j, const Element &elem) {

	const Matrix<Element> Ai = (*m_A)[i];
	const Matrix<Element> Aj = (*m_A)[j];
	const RLWETrapdoorPair<Element> Ti = (*m_T)[i];

	size_t m = Ai.GetCols();
	size_t k = m - 2;
	size_t n = elem.GetRingDimension();
	auto zero_alloc = Element::MakeAllocator(elem.GetParams(), EVALUATION);

	//generate a row vector of discrete Gaussian ring elements
	//YSP this can be done using discrete Gaussian allocator later - after the dgg allocator is updated to use the same dgg instance
	//DBC all the following have insignificant timing
	Matrix<Element> ej(zero_alloc, 1, m);

	#pragma omp parallel for
	for(size_t i=0; i<m; i++) {
		ej(0,i) = Element(m_dgg, elem.GetParams(), COEFFICIENT);
		ej(0,i).SwitchFormat();
	}

	const Matrix<Element> &bj = Aj.ScalarMult(elem) + ej;

	shared_ptr<Matrix<Element>> result(new Matrix<Element>(zero_alloc, m, m));

	//DBC: this loop takes all the time in encode
	//TODO (dcousins): move gaussj generation out of the loop to enable parallelisation
	#pragma omp parallel for schedule(dynamic)
	for(size_t i=0; i<m; i++) {
		// the following takes approx 250 msec
		const Matrix<Element> &gaussj = RLWETrapdoorUtility<Element>::GaussSamp(n,k,Ai,Ti,bj(0,i), m_dgg, m_dggLargeSigma, m_base);
		// the following takes no time
		for(size_t j=0; j<m; j++) {
			(*result)(j,i) = gaussj(j,0);
		}
	}

	return result;

};

}

#endif
