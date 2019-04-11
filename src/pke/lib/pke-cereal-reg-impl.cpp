/*
 * pke-cereal-reg-impl.cpp
 *
 *  Created on: Apr 10, 2019
 *      Author: gerardryan
 */

#include "palisade.h"
#include "cryptocontext.h"

// type registrations, by scheme

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersNull<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeNull<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmNull<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmParamsGenNull<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHENull<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPLeveledSHEAlgorithmNull<lbcrypto::Poly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersNull<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeNull<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmNull<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmParamsGenNull<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHENull<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPLeveledSHEAlgorithmNull<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersNull<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeNull<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmNull<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmParamsGenNull<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHENull<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPLeveledSHEAlgorithmNull<lbcrypto::DCRTPoly>);

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

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersStehleSteinfeld<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeStehleSteinfeld<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmStSt<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHEStSt<lbcrypto::Poly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersStehleSteinfeld<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeStehleSteinfeld<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmStSt<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHEStSt<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersStehleSteinfeld<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeStehleSteinfeld<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmStSt<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHEStSt<lbcrypto::DCRTPoly>);
