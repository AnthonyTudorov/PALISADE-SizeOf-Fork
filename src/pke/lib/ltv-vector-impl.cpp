/*
 * ltv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ltv.cpp"

namespace lbcrypto {
template class LPCryptoParametersLTV<ILVector2n>;
template class LPPublicKeyEncryptionSchemeLTV<ILVector2n>;
template class LPAlgorithmLTV<ILVector2n>;
template class LPAlgorithmPRELTV<ILVector2n>;
template class LPAlgorithmFHELTV<ILVector2n>;
template class LPAlgorithmSHELTV<ILVector2n>;
template class LPLeveledSHEAlgorithmLTV<ILVector2n>;
}
