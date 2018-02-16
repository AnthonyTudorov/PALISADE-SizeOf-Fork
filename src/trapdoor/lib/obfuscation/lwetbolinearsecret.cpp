/**
 * @file lwetbolinearsecret.cpp Implementation of token-based obfuscation of linear functions (secret-key version)
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

#ifndef LBCRYPTO_OBFUSCATE_LWETBOLINEARSECRET_CPP
#define LBCRYPTO_OBFUSCATE_LWETBOLINEARSECRET_CPP

#include "lwetbolinearsecret.h"

namespace lbcrypto {

usint LWETBOLinearSecret::GetLogModulus() const {
	double q = m_modulus.ConvertToDouble();
	usint logModulus = floor(log2(q - 1.0) + 1.0);
	return logModulus;
}

LWETBOLinearSecret::LWETBOLinearSecret(usint N, usint n, usint wmax, usint pmax) : m_N(N), m_n(n), m_wmax(wmax), m_pmax(pmax) {

	double q = EstimateModulus();

	m_modulus = FirstPrime<NativeInteger>(floor(log2(q - 1.0) + 1.0), 2*m_n);

	m_dgg.SetStd(3.2);

}

double LWETBOLinearSecret::EstimateModulus() {

	//distribution parameter
	double sigma = 3.2;

	//assurance measure
	double alpha = 36;

	//Bound of the Gaussian error
	double Berr = sigma*sqrt(alpha);

	m_p = m_N*m_wmax*m_pmax;

	//Correctness constraint
	return 4*m_N*m_wmax*m_p*Berr;

};

LWETBOKeys LWETBOLinearSecret::KeyGen() const
{

	DiscreteUniformGeneratorImpl<NativeInteger,NativeVector> dug;
	dug.SetModulus(m_modulus);

	// discrete uniform generator is used to generate the secret keys
	NativeMatrixPtr secretKey(new Matrix<NativeInteger>([&]() { return dug.GenerateInteger(); }, m_n,m_N));

	NativeMatrixPtr publicRandomVector(new Matrix<NativeInteger>([&]() { return dug.GenerateInteger(); }, 1,m_n));

	LWETBOKeys keys;
	keys.m_secretKey = secretKey;
	keys.m_publicRandomVector = publicRandomVector;

	return keys;

}

shared_ptr<Matrix<NativeInteger>> LWETBOLinearSecret::TokenGen(const NativeMatrixPtr keys, const NativeMatrixPtr input) const
{

	NativeMatrixPtr token(new Matrix<NativeInteger>(NativeInteger::Allocator, m_n, 1));

	for (size_t ni = 0; ni < keys->GetRows(); ni++)
		for (size_t Ni = 0; Ni < keys->GetCols(); Ni++)
			(*token)(ni,0) = (*token)(ni,0).ModAdd((*keys)(ni,Ni).ModMul((*input)(Ni,0),m_modulus),m_modulus);

	return token;

}

shared_ptr<Matrix<NativeInteger>> LWETBOLinearSecret::Obfuscate(const LWETBOKeys &keyPair, const NativeMatrixPtr weights) const
{

	NativeMatrixPtr ciphertext(new Matrix<NativeInteger>(NativeInteger::Allocator, m_N, 1));

	for (size_t Ni = 0; Ni < keyPair.m_secretKey->GetCols(); Ni++)
	{

		for (size_t ni = 0; ni < keyPair.m_secretKey->GetRows(); ni++){
			(*ciphertext)(Ni,0) = (*ciphertext)(Ni,0).ModAdd((*keyPair.m_secretKey)(ni,Ni).ModMul((*keyPair.m_publicRandomVector)(0,ni),m_modulus),m_modulus);
		}

		(*ciphertext)(Ni,0) = (*ciphertext)(Ni,0).ModAdd(NativeInteger(m_p)*m_dgg.GenerateInteger(m_modulus),m_modulus);

		(*ciphertext)(Ni,0) = (*ciphertext)(Ni,0).ModAdd((*weights)(Ni,0),m_modulus);

	}

	return ciphertext;

}

NativeInteger LWETBOLinearSecret::Evaluate(const NativeMatrixPtr input, const NativeMatrixPtr ciphertext,
		const NativeMatrixPtr publicKey, const NativeMatrixPtr token) const{

	NativeInteger result;

	for (size_t Ni = 0; Ni < m_N; Ni++)
		result = result.ModAdd((*input)(Ni,0).ModMul((*ciphertext)(Ni,0),m_modulus),m_modulus);

	for (size_t ni = 0; ni < m_n; ni++)
		result = result.ModSub((*publicKey)(0,ni).ModMul((*token)(ni,0),m_modulus),m_modulus);

	NativeInteger halfQ(m_modulus >> 1);

	if (result>halfQ)
		result=result.ModSub(m_modulus,m_p);
	else
		result=result.Mod(m_p);

	return result.Mod(m_p);

}

NativeInteger LWETBOLinearSecret::EvaluateClear(const NativeMatrixPtr input, const NativeMatrixPtr weights) const{

	NativeInteger result;

	for (size_t Ni = 0; Ni < m_N; Ni++)
		result += (*input)(Ni,0)*(*weights)(Ni,0);

	return result;

}

}

#endif
