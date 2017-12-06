/*
* @file bfvrns-vector-impl.cpp - vector implementation for the BFVrns scheme.
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
#include "bfvrns.cpp"

namespace lbcrypto {

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(){
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns &rhs){
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(shared_ptr<typename Poly::Params> params,
		const BigInteger &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(shared_ptr<typename Poly::Params> params,
		shared_ptr<EncodingParams> encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

// Parameter generation for FV-RNS
template <>
bool LPCryptoParametersBFVrns<Poly>::PrecomputeCRTTables(){
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
LPPublicKeyEncryptionSchemeBFVrns<Poly>::LPPublicKeyEncryptionSchemeBFVrns(){
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
bool LPAlgorithmParamsGenBFVrns<Poly>::ParamsGen(shared_ptr<LPCryptoParameters<Poly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrns<Poly>::Encrypt(const LPPublicKey<Poly> publicKey,
		Poly ptxt) const
{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
DecryptResult LPAlgorithmBFVrns<Poly>::Decrypt(const LPPrivateKey<Poly> privateKey,
		const Ciphertext<Poly> ciphertext,
		Poly *plaintext) const
{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
shared_ptr<Ciphertext<Poly>> LPAlgorithmBFVrns<Poly>::Encrypt(const shared_ptr<LPPrivateKey<Poly>> privateKey,
		Poly ptxt) const
{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalMult(const Ciphertext<Poly> ciphertext1,
	const Ciphertext<Poly> ciphertext2) const {
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

shared_ptr<Ciphertext<Poly>> LPAlgorithmSHEBFVrns<Poly>::EvalAdd(const shared_ptr<Ciphertext<Poly>> ct,
	const Plaintext pt) const{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
shared_ptr<Ciphertext<Poly>> LPAlgorithmSHEBFVrns<Poly>::EvalSub(const shared_ptr<Ciphertext<Poly>> ct,
	const Plaintext pt) const{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
shared_ptr<LPEvalKey<Poly>> LPAlgorithmSHEBFVrns<Poly>::KeySwitchGen(const shared_ptr<LPPrivateKey<Poly>> originalPrivateKey,
	const shared_ptr<LPPrivateKey<Poly>> newPrivateKey) const {
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
shared_ptr<Ciphertext<Poly>> LPAlgorithmSHEBFVrns<Poly>::KeySwitch(const shared_ptr<LPEvalKey<Poly>> keySwitchHint,
	const shared_ptr<Ciphertext<Poly>> cipherText) const{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template <>
shared_ptr<Ciphertext<Poly>> LPAlgorithmSHEBFVrns<Poly>::EvalMultAndRelinearize(const shared_ptr<Ciphertext<Poly>> ct1,
	const shared_ptr<Ciphertext<Poly>> ct, const shared_ptr<vector<shared_ptr<LPEvalKey<Poly>>>> ek) const{
	std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead.";
	throw std::runtime_error(errMsg);
}

template class LPCryptoParametersBFVrns<Poly>;
template class LPPublicKeyEncryptionSchemeBFVrns<Poly>;
template class LPAlgorithmBFVrns<Poly>;
template class LPAlgorithmSHEBFVrns<Poly>;
template class LPAlgorithmParamsGenBFVrns<Poly>;

}
