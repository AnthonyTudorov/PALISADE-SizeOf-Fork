/*
* @file fv-dcrtpoly-impl.cpp - vector array implementation for the FV scheme.
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
#include "fv.cpp"

namespace lbcrypto {

template <>
LPCryptoParametersFV<DCRTPoly>::LPCryptoParametersFV() {
	std::string errMsg = "FV does not support DCRTPoly. Use Poly instead.";
	throw std::runtime_error(errMsg);
}

template <>
LPCryptoParametersFV<DCRTPoly>::LPCryptoParametersFV(const LPCryptoParametersFV &rhs) {
	std::string errMsg = "FV does not support DCRTPoly. Use Poly instead.";
	throw std::runtime_error(errMsg);
}

template <>
LPCryptoParametersFV<DCRTPoly>::LPCryptoParametersFV(shared_ptr<typename DCRTPoly::Params> params,
	const BigInteger &plaintextModulus,
	float distributionParameter,
	float assuranceMeasure,
	float securityLevel,
	usint relinWindow,
	const BigInteger &delta,
	MODE mode,
	const BigInteger &bigModulus ,
	const BigInteger &bigRootOfUnity,
	const BigInteger &bigModulusArb,
	const BigInteger &bigRootOfUnityArb,
	int depth,
	int maxDepth) {
		std::string errMsg = "FV does not support DCRTPoly. Use Poly instead.";
		throw std::runtime_error(errMsg);
}

template <>
LPCryptoParametersFV<DCRTPoly>::LPCryptoParametersFV(shared_ptr<typename DCRTPoly::Params> params,
	shared_ptr<EncodingParams> encodingParams,
	float distributionParameter,
	float assuranceMeasure,
	float securityLevel,
	usint relinWindow,
	const BigInteger &delta,
	MODE mode,
	const BigInteger &bigModulus ,
	const BigInteger &bigRootOfUnity,
	const BigInteger &bigModulusArb,
	const BigInteger &bigRootOfUnityArb,
	int depth,
	int maxDepth)	{
		std::string errMsg = "FV does not support DCRTPoly. Use Poly instead.";
		throw std::runtime_error(errMsg);
	}

template <>
LPPublicKeyEncryptionSchemeFV<DCRTPoly>::LPPublicKeyEncryptionSchemeFV(){
		std::string errMsg = "FV does not support DCRTPoly. Use Poly instead.";
		throw std::runtime_error(errMsg);
	}

template class LPCryptoParametersFV<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeFV<DCRTPoly>;
template class LPAlgorithmFV<DCRTPoly>;
template class LPAlgorithmParamsGenFV<DCRTPoly>;

}
