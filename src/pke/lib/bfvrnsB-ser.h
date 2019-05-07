/*
* @file bfvrnsB-ser.h - serialize BFVrnsB; include this in any app that needs to serialize this scheme
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

#ifndef LBCRYPTO_CRYPTO_BFVRNSBSER_H
#define LBCRYPTO_CRYPTO_BFVRNSBSER_H

#include "palisade.h"
#include "utils/serial.h"

extern template class lbcrypto::LPCryptoParametersBFVrnsB<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeBFVrnsB<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmBFVrnsB<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmSHEBFVrnsB<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmMultipartyBFVrnsB<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmParamsGenBFVrnsB<lbcrypto::DCRTPoly>;

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBFVrnsB<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeBFVrnsB<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmBFVrnsB<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmSHEBFVrnsB<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmMultipartyBFVrnsB<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPAlgorithmParamsGenBFVrnsB<lbcrypto::DCRTPoly>);

#endif
