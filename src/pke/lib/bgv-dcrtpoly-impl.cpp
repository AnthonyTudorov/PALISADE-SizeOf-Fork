/*
 * @file bgv-dcrtpoly-impl.cpp - BGV dcrtpoly implementation.
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

#include "cryptocontext.h"
#include "bgv.cpp"

namespace lbcrypto {
template class LPCryptoParametersBGV<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBGV<DCRTPoly>;
template class LPAlgorithmBGV<DCRTPoly>;

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPREBGV<DCRTPoly>::ReKeyGen(const LPPublicKey<DCRTPoly> newPK,
	const LPPrivateKey<DCRTPoly> origPrivateKey) const
{
	// Get crypto context of new public key.
	auto cc = newPK->GetCryptoContext();

	// Create an evaluation key that will contain all the re-encryption key elements.
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	// Get crypto and elements parameters
	const shared_ptr<LPCryptoParametersRLWE<DCRTPoly>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(newPK->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();

	// Get parameters needed for PRE key gen
	// r = relinWindow
	usint relinWin = cryptoParamsLWE->GetRelinWindow();
	// nBits = log2(q), where q: ciphertext modulus
	usint nBits = elementParams->GetModulus().GetLengthForBase(2);

	// K = log2(q)/r, i.e., number of digits in PRE decomposition
	usint K = nBits / relinWin;
	if (nBits % relinWin > 0)
		K++;

	// minus_skElem = -s(2^r)^i, s: secret key, r: relin window
	DCRTPoly s = origPrivateKey->GetPrivateElement();
	DCRTPoly minus_s = s.Negate();

	std::vector<DCRTPoly> evalKeyElementsA(K);
	std::vector<DCRTPoly> evalKeyElementsB(K);

	// The re-encryption key is K ciphertexts, one for each -s(2^r)^i
	for (usint i=0; i<K; i++) {
		int numTowers = minus_s.GetAllElements().size();
		BigInteger bb = BigInteger(1) << i*relinWin;
		vector<NativeInteger> b(numTowers);

		for (int j=0; j<numTowers; j++) {
			auto mod = minus_s.ElementAtIndex(j).GetModulus();
			auto bbmod = bb.Mod(mod);
			b[j] = bbmod.ConvertToInt();
		}

		auto tmp = cc->GetEncryptionAlgorithm()->Encrypt(newPK, minus_s.Times(b));
		evalKeyElementsA[i] = tmp->GetElements()[1];
		evalKeyElementsB[i] = tmp->GetElements()[0];
	}

	ek->SetAVector(std::move(evalKeyElementsA));
	ek->SetBVector(std::move(evalKeyElementsB));

	return std::move(ek);
}

}
