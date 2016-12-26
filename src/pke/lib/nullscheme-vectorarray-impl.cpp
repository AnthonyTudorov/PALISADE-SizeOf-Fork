/*
 * nullscheme-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "nullscheme.h"

namespace lbcrypto {
template class LPCryptoParametersNull<ILVectorArray2n>;
template class LPPublicKeyEncryptionSchemeNull<ILVectorArray2n>;
template class LPAlgorithmNull<ILVectorArray2n>;
}
