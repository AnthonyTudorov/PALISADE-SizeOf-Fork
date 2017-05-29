/*
 * pubkeylp-vector-impl.cpp
 *
 *  Created on: May 22, 2017
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "pubkeylp.cpp"

namespace lbcrypto {
extern template class CryptoContext<ILVectorArray2n>;

template class LPPublicKey<ILVectorArray2n>;
template class LPEvalKeyRelin<ILVectorArray2n>;
template class LPEvalKeyNTRURelin<ILVectorArray2n>;
}

