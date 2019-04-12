/*
 * @file pubkeylp-dcrtpoly-impl.cpp - public key dcrtpoly implementation
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
#include "pubkeylp.cpp"

namespace lbcrypto {
extern template class CryptoContextImpl<DCRTPoly>;

template class LPPublicKeyImpl<DCRTPoly>;
template class LPPrivateKeyImpl<DCRTPoly>;
template class LPEvalKeyRelinImpl<DCRTPoly>;
template class LPEvalKeyNTRUImpl<DCRTPoly>;
template class LPEvalKeyNTRURelinImpl<DCRTPoly>;
template class LPSHEAlgorithm<DCRTPoly>;
}

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParameters<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersRLWE<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyRelinImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyNTRUImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyNTRURelinImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::DCRTPoly>, lbcrypto::LPEvalKeyRelinImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::DCRTPoly>, lbcrypto::LPEvalKeyNTRUImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::DCRTPoly>, lbcrypto::LPEvalKeyNTRURelinImpl<lbcrypto::DCRTPoly>);

CEREAL_REGISTER_DYNAMIC_INIT(pubkeylpdcrtpoly);

