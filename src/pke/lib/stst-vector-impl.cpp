/*
 * stst-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ltv.h"
#include "stst.h"

namespace lbcrypto {
template class CryptoContext<ILVector2n>;
template class Ciphertext<ILVector2n>;

template class LPAlgorithmLTV<ILVector2n>;
template class LPPublicKeyEncryptionSchemeLTV<ILVector2n>;
template class LPAlgorithmPRELTV<ILVector2n>;
template class LPAlgorithmSHELTV<ILVector2n>;
template class LPAlgorithmFHELTV<ILVector2n>;
template class LPLeveledSHEAlgorithmLTV<ILVector2n>;

template class LPCryptoParametersRLWE<ILVector2n>;

template class LPCryptoParametersStehleSteinfeld<ILVector2n>;
template class LPEncryptionAlgorithmStehleSteinfeld<ILVector2n>;
}
