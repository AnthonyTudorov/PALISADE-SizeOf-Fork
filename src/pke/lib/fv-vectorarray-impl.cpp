/*
 * fv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "fv.cpp"

namespace lbcrypto {
template class LPCryptoParametersFV<ILVectorArray2n>;
template class LPPublicKeyEncryptionSchemeFV<ILVectorArray2n>;
template class LPAlgorithmFV<ILVectorArray2n>;
template class LPAlgorithmParamsGenFV<ILVectorArray2n>;
}
