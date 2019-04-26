/*
 * @file pubkeylp-poly-impl.cpp - public key poly implementation.
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
extern template class CryptoContextImpl<Poly>;

template class LPPublicKeyImpl<Poly>;
template class LPPrivateKeyImpl<Poly>;
template class LPEvalKeyRelinImpl<Poly>;
template class LPEvalKeyNTRUImpl<Poly>;
template class LPEvalKeyNTRURelinImpl<Poly>;
template class LPSHEAlgorithm<Poly>;

extern template class CryptoContextImpl<NativePoly>;

template class LPPublicKeyImpl<NativePoly>;
template class LPPrivateKeyImpl<NativePoly>;
template class LPEvalKeyRelinImpl<NativePoly>;
template class LPEvalKeyNTRUImpl<NativePoly>;
template class LPEvalKeyNTRURelinImpl<NativePoly>;
template class LPSHEAlgorithm<NativePoly>;

}

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParameters<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParameters<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersRLWE<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersRLWE<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyImpl<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyRelinImpl<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyRelinImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyNTRUImpl<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyNTRUImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyNTRURelinImpl<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyNTRURelinImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::Poly>, lbcrypto::LPEvalKeyRelinImpl<lbcrypto::Poly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::NativePoly>, lbcrypto::LPEvalKeyRelinImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::Poly>, lbcrypto::LPEvalKeyNTRUImpl<lbcrypto::Poly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::NativePoly>, lbcrypto::LPEvalKeyNTRUImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::Poly>, lbcrypto::LPEvalKeyNTRURelinImpl<lbcrypto::Poly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::LPEvalKeyImpl<lbcrypto::NativePoly>, lbcrypto::LPEvalKeyNTRURelinImpl<lbcrypto::NativePoly>);
