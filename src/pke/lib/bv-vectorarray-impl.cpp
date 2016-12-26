/*
 * bv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "bv.cpp"

namespace lbcrypto {
template class LPCryptoParametersBV<ILVectorArray2n>;
template class LPPublicKeyEncryptionSchemeBV<ILVectorArray2n>;
template class LPAlgorithmBV<ILVectorArray2n>;
}
