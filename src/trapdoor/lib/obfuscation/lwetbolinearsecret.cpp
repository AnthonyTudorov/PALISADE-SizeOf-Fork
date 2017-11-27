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

LWETBOLinearSecret::LWETBOLinearSecret(usint N, usint n, usint wmax, usint p) : m_N(N), m_n(n), m_wmax(wmax), m_p(p) {

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

	//Correctness constraint
	auto qCorrectness = [&](uint32_t N, uint32_t wmax, uint32_t p, uint32_t n) -> double { return  4*N*wmax*p*Berr;  };

	return qCorrectness(m_N,m_wmax,m_p,m_n);

};

LWETBOKeyPair LWETBOLinearSecret::KeyGen() const
{

	DiscreteUniformGeneratorImpl<NativeInteger,native_int::BigVector> dug;
	dug.SetModulus(m_modulus);

	// discrete uniform generator is used to generate the secret keys
	NativeMatrixPtr secretKey(new Matrix<NativeInteger>([&]() { return make_unique<NativeInteger>(dug.GenerateInteger()); }, m_n,m_N));

	NativeMatrixPtr publicKey(new Matrix<NativeInteger>([&]() { return make_unique<NativeInteger>(dug.GenerateInteger()); }, 1,m_n));

	LWETBOKeyPair keyPair;
	keyPair.m_secretKey = secretKey;
	keyPair.m_publicKey = publicKey;

	return keyPair;

}

shared_ptr<Matrix<native_int::BigInteger>> LWETBOLinearSecret::TokenGen(const NativeMatrixPtr keys, const NativeMatrixPtr input) const
{

	NativeMatrixPtr token(new Matrix<NativeInteger>([&]() { return make_unique<NativeInteger>(); }, m_n,1));

	for (size_t ni = 0; ni < keys->GetRows(); ni++)
		for (size_t Ni = 0; Ni < keys->GetCols(); Ni++)
			(*token)(ni,0) = (*token)(ni,0).ModAdd((*keys)(ni,Ni).ModMul((*input)(Ni,0),m_modulus),m_modulus);

	return token;

}

shared_ptr<Matrix<native_int::BigInteger>> LWETBOLinearSecret::Encrypt(const LWETBOKeyPair &keyPair, const NativeMatrixPtr weights) const
{

	NativeMatrixPtr ciphertext(new Matrix<NativeInteger>([&]() { return make_unique<NativeInteger>(); }, m_N,1));

	for (size_t Ni = 0; Ni < keyPair.m_secretKey->GetCols(); Ni++)
	{

		for (size_t ni = 0; ni < keyPair.m_secretKey->GetRows(); ni++){
			(*ciphertext)(Ni,0) = (*ciphertext)(Ni,0).ModAdd((*keyPair.m_secretKey)(ni,Ni).ModMul((*keyPair.m_publicKey)(0,ni),m_modulus),m_modulus);
		}

		(*ciphertext)(Ni,0) = (*ciphertext)(Ni,0).ModAdd(m_wmax*m_dgg.GenerateInt(),m_modulus);

		(*ciphertext)(Ni,0) = (*ciphertext)(Ni,0).ModAdd((*weights)(Ni,0),m_modulus);

	}

	return ciphertext;

}

native_int::BigInteger LWETBOLinearSecret::Evaluate(const NativeMatrixPtr input, const NativeMatrixPtr ciphertext,
		const NativeMatrixPtr publicKey, const NativeMatrixPtr token) const{

	NativeInteger result;

	for (size_t Ni = 0; Ni < m_N; Ni++)
		result = result.ModAdd((*input)(Ni,0).ModMul((*ciphertext)(Ni,0),m_modulus),m_modulus);

	for (size_t ni = 0; ni < m_N; ni++)
		result = result.ModSub((*publicKey)(0,ni).ModMul((*token)(ni,0),m_modulus),m_modulus);

	return result.Mod(m_wmax);

}

native_int::BigInteger LWETBOLinearSecret::EvaluateClear(const NativeMatrixPtr input, const NativeMatrixPtr weights) const{

	NativeInteger result;

	for (size_t Ni = 0; Ni < m_N; Ni++)
		result = result.ModAdd((*input)(Ni,0).ModMul((*weights)(Ni,0),m_modulus),m_modulus);

	return result.Mod(m_wmax);

}

}

#endif
