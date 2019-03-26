/*
* @file bfv-poly-impl.cpp - poly implementation for the BFV scheme.
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
#include "bfv.cpp"

namespace lbcrypto {

template<>
LPPublicKeyEncryptionSchemeBFV<Poly>::LPPublicKeyEncryptionSchemeBFV() : LPPublicKeyEncryptionScheme<Poly>() {
	this->m_algorithmParamsGen = new LPAlgorithmParamsGenBFV<Poly>();
}

template<>
LPPublicKeyEncryptionSchemeBFV<NativePoly>::LPPublicKeyEncryptionSchemeBFV() : LPPublicKeyEncryptionScheme<NativePoly>() {
	this->m_algorithmParamsGen = new LPAlgorithmParamsGenBFV<NativePoly>();
}

template class LPCryptoParametersBFV<Poly>;
template class LPPublicKeyEncryptionSchemeBFV<Poly>;
template class LPAlgorithmBFV<Poly>;
template class LPAlgorithmParamsGenBFV<Poly>;

template class LPCryptoParametersBFV<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFV<NativePoly>;
template class LPAlgorithmBFV<NativePoly>;
template class LPAlgorithmParamsGenBFV<NativePoly>;
}

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBFV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBFV<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeBFV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeBFV<lbcrypto::NativePoly>);
