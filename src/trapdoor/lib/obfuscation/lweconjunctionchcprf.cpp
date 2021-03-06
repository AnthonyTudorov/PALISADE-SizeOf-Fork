/**
 * @file lweconjunctionchcprf.cpp Implementation of conjunction constraint-hiding constrained PRFs as described in https://eprint.iacr.org/2017/143.pdf
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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

#include "obfuscation/lweconjunctionchcprf.h"

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
	double qEst = EstimateRingModulus(n);
	m_elemParams = GenerateElemParams(qEst, n);

	double modulus = m_elemParams->GetModulus().ConvertToDouble();

	// Initialize m_dggLargeSigma
	usint k = floor(log2(modulus-1.0)+1.0);
	usint m = ceil(k/log2(base)) + 2;

	double c = (base + 1) * SIGMA;
	double s = SPECTRAL_BOUND(n, m - 2, base);

	if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
		m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
	else
		m_dggLargeSigma = m_dgg;

	size_t size = m_elemParams->GetParams().size();

	BigInteger q(m_elemParams->GetModulus());

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);
	for (size_t i = 0; i < size; i++){
		moduli[i] = m_elemParams->GetParams()[i]->GetModulus();
		roots[i] = m_elemParams->GetParams()[i]->GetRootOfUnity();
	}

	const BigInteger deltaBig = q.DividedBy(NativeInteger(2));

	std::vector<NativeInteger> CRTDeltaTable(size);

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(m_elemParams->GetParams()[i]->GetModulus().ConvertToInt());
		BigInteger deltaI = deltaBig.Mod(qi);
		CRTDeltaTable[i] = NativeInteger(deltaI.ConvertToInt());
	}

	m_CRTDeltaTable = CRTDeltaTable;

	NativeInteger p = NativeInteger(2);

	if (moduli[0].GetMSB() < 45)
	{
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<double> CRTDecryptionFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((q.DividedBy(qi)).ModInverse(qi) * BigInteger(p)).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionFloatTable[i] = (double)numerator/(double)denominator;
		}
		m_CRTDecryptionFloatTable = CRTDecryptionFloatTable;
	}
	else if (moduli[0].GetMSB() < 58)
	{
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<long double> CRTDecryptionExtFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((q.DividedBy(qi)).ModInverse(qi) * BigInteger(p)).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionExtFloatTable[i] = (long double)numerator/(long double)denominator;
		}
		m_CRTDecryptionExtFloatTable = CRTDecryptionExtFloatTable;
	}
	else
	{
#ifndef NO_QUADMATH
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<QuadFloat> CRTDecryptionQuadFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((q.DividedBy(qi)).ModInverse(qi) * BigInteger(p)).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionQuadFloatTable[i] = ext_double::quadFloatFromInt64(numerator)/ext_double::quadFloatFromInt64(denominator);
		}
		m_CRTDecryptionQuadFloatTable = CRTDecryptionQuadFloatTable;
#else
			PALISADE_THROW(math_error, "LWEConjunctionCHCPRFAlgorithm: Number of bits in CRT moduli should be in < 58 for this architecture");
	
#endif		
	}

	//compute the table of integer factors floor[(p*[(Q/qi)^{-1}]_qi)/qi]_p - used in decryption

	std::vector<NativeInteger> qDecryptionInt(size);
	std::vector<NativeInteger> qDecryptionIntPrecon(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = q / qi;
		BigInteger quotient = (divBy.ModInverse(qi))*BigInteger(p)/qi;
		qDecryptionInt[vi] = quotient.Mod(p).ConvertToInt();
		qDecryptionIntPrecon[vi] = qDecryptionInt[vi].PrepModMulPreconOptimized(p);
	}

	m_CRTDecryptionIntTable = qDecryptionInt;
	m_CRTDecryptionIntPreconTable = qDecryptionIntPrecon;

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
shared_ptr<vector<vector<Element>>> LWEConjunctionCHCPRFAlgorithm<Element>::KeyGen() {

	shared_ptr<vector<vector<Element>>> s(new vector<vector<Element>>());

	for (usint i = 0; i < m_adjustedLength; i++) {
		vector<Element> s_i;

		for (usint k = 0; k < m_chunkExponent; k++) {
			Element s_ik = Element(m_dgg, m_elemParams, COEFFICIENT);
			s_ik.SwitchFormat();

			s_i.push_back(s_ik);
		}

		s->push_back(s_i);
	}

	return s;

};


template <class Element>
shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> LWEConjunctionCHCPRFAlgorithm<Element>::Constrain(const shared_ptr<vector<vector<Element>>> s, const std::string &pattern) {

	shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> D(new vector<vector<shared_ptr<Matrix<Element>>>>());

	for (usint i = 0; i < m_adjustedLength; i++) {
		// current chunk of cleartext pattern
		std::string chunk = pattern.substr(i * m_chunkSize, m_chunkSize);

		// build a chunk mask that maps "10??" to "1100" - ones correspond to non-wildcard character
		std::string chunkTemp = replaceChar(chunk, '0', '1');
		chunkTemp = replaceChar(chunkTemp, '?', '0');
		// store the mask as integer for bitwise operations
		usint chunkMask = std::stoi(chunkTemp, nullptr, 2);

		// build a chunk target that maps "10??" to "1000" - replacing wildcard character by 0
		chunkTemp = replaceChar(chunk, '?', '0');
		usint chunkTarget = std::stoi(chunkTemp, nullptr, 2);

		vector<shared_ptr<Matrix<Element>>> D_i;

		for (usint k = 0; k < m_chunkExponent; k++) {
			Element s_ik = (*s)[i][k];

			if ((k & chunkMask) != chunkTarget) {
				s_ik = Element(m_dgg, m_elemParams, COEFFICIENT);
				s_ik.SwitchFormat();
			}

			shared_ptr<Matrix<Element>> D_ik = Encode(i, i + 1, s_ik);
			D_i.push_back(D_ik);
		}

		D->push_back(D_i);
	}

	return D;

};

template <class Element>
shared_ptr<vector<NativePoly>> LWEConjunctionCHCPRFAlgorithm<Element>::Evaluate(const shared_ptr<vector<vector<Element>>> s, const std::string &input) const {

	Element yCurrent;

	for (usint i = 0; i < m_adjustedLength; i++) {
		std::string chunk = input.substr(i * m_chunkSize, m_chunkSize);
		int k = std::stoi(chunk, nullptr, 2);

		if (i == 0)
			yCurrent = (*s)[i][k];
		else
			yCurrent *= (*s)[i][k];
	}

	Element y = (*m_A)[m_adjustedLength](0,1)*yCurrent;

	return TransformMatrixToPRFOutput(y);

}


template <class Element>
shared_ptr<vector<NativePoly>> LWEConjunctionCHCPRFAlgorithm<Element>::Evaluate(const shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> D, const std::string &input) const {

	Matrix<Element> y = (*m_A)[0];

	for (usint i = 0; i < m_adjustedLength; i++) {
		std::string chunk = input.substr(i * m_chunkSize, m_chunkSize);
		int k = std::stoi(chunk, nullptr, 2);

		y = y * *(*D)[i][k];
	}

	return TransformMatrixToPRFOutput(y(0,1));

};


template <class Element>
double LWEConjunctionCHCPRFAlgorithm<Element>::EstimateRingModulus(usint n) {

	//smoothing parameter - also standard deviation for noise Elementnomials
	double sigma = SIGMA;

	//assurance measure
	double alpha = 36;

	//empirical parameter
	double beta = 6;

	//Bound of the Gaussian error Elementnomial
	double Berr = sigma*sqrt(alpha);

    //probability of hitting the "danger" zone that affects the rounding result
	double Pe = 1 << 20;

	uint32_t length = m_adjustedLength;
	uint32_t base = m_base;

	//Correctness constraint
	auto qCorrectness = [&](uint32_t n, uint32_t m, uint32_t k) -> double { return  1024*Pe*Berr*pow(sqrt(m*n)*beta*SPECTRAL_BOUND(n,m-2,base),length-1);  };

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



template <class Element>
void LWEConjunctionCHCPRFAlgorithm<Element>::EncodingParamsGen() {

	const shared_ptr<typename Element::Params> params = m_elemParams;
	usint base = m_base;
	usint stddev = m_dgg.GetStd();

	for(size_t i = 0; i <= m_adjustedLength; i++) {
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
	size_t n = GetRingDimension();
	auto zero_alloc = Element::Allocator(elem.GetParams(), EVALUATION);

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

template <class Element>
shared_ptr<vector<NativePoly>> LWEConjunctionCHCPRFAlgorithm<Element>::TransformMatrixToPRFOutput(const Element &input) const {

	const std::vector<double> &lyamTable = m_CRTDecryptionFloatTable;
	const std::vector<long double> &lyamExtTable = m_CRTDecryptionExtFloatTable;
#ifndef NO_QUADMATH
	const std::vector<QuadFloat> &lyamQuadTable = m_CRTDecryptionQuadFloatTable;
#endif
	const std::vector<NativeInteger> &invTable = m_CRTDecryptionIntTable;
	const std::vector<NativeInteger> &invPreconTable = m_CRTDecryptionIntPreconTable;

	shared_ptr<vector<NativePoly>> result(new vector<NativePoly>(1));

	//for (size_t i = 0; i < matrix.GetCols(); i++) {
	//	(*result)[i] = matrix(0, i).ScaleAndRound(NativeInteger(2),invTable,lyamTable,invPreconTable,lyamQuadTable,lyamExtTable);
	//}

	// For PRF, it is sufficient to use 128 coefficients; we currently use n coefficients

	auto element = input;
	element.SwitchFormat();

#ifndef NO_QUADMATH
	(*result)[0] = element.ScaleAndRound(NativeInteger(2),invTable,lyamTable,invPreconTable,lyamQuadTable,lyamExtTable);
#else
	(*result)[0] = element.ScaleAndRound(NativeInteger(2),invTable,lyamTable,invPreconTable,lyamExtTable);
#endif

	return result;

};

}

#endif
