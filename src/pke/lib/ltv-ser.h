/*
* @file ltv-ser.h - serialize LTV; include this in any app that needs to serialize this scheme
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

#ifndef LBCRYPTO_CRYPTO_LTVSER_H
#define LBCRYPTO_CRYPTO_LTVSER_H

#include "palisade.h"
#include "utils/serial.h"

extern template class lbcrypto::LPCryptoParametersLTV<lbcrypto::Poly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeLTV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmLTV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmPRELTV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmSHELTV<lbcrypto::Poly>;
extern template class lbcrypto::LPLeveledSHEAlgorithmLTV<lbcrypto::Poly>;

extern template class lbcrypto::LPCryptoParametersLTV<lbcrypto::NativePoly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeLTV<lbcrypto::NativePoly>;
extern template class lbcrypto::LPAlgorithmLTV<lbcrypto::NativePoly>;
extern template class lbcrypto::LPAlgorithmPRELTV<lbcrypto::NativePoly>;
extern template class lbcrypto::LPAlgorithmSHELTV<lbcrypto::NativePoly>;
extern template class lbcrypto::LPLeveledSHEAlgorithmLTV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPCryptoParametersLTV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeLTV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmLTV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmPRELTV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmSHELTV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPLeveledSHEAlgorithmLTV<lbcrypto::DCRTPoly>;

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersLTV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeLTV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmParamsGenLTV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmLTV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmPRELTV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHELTV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPLeveledSHEAlgorithmLTV<lbcrypto::Poly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersLTV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeLTV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmParamsGenLTV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmLTV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmPRELTV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHELTV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPLeveledSHEAlgorithmLTV<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersLTV<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeLTV<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmParamsGenLTV<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmLTV<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmPRELTV<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHELTV<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPLeveledSHEAlgorithmLTV<lbcrypto::DCRTPoly>);

#endif
