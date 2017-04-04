/*
 * ltv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ltv.cpp"

namespace lbcrypto {
template class LPCryptoParametersLTV<ILVectorArray2n>;
template class LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n>;
template class LPAlgorithmLTV<ILVectorArray2n>;
template class LPAlgorithmPRELTV<ILVectorArray2n>;
template class LPAlgorithmSHELTV<ILVectorArray2n>;
template class LPLeveledSHEAlgorithmLTV<ILVectorArray2n>;
}
