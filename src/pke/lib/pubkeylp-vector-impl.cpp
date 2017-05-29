/*
 * pubkeylp-vector-impl.cpp
 *
 *  Created on: May 22, 2017
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "pubkeylp.cpp"

namespace lbcrypto {
extern template class CryptoContext<ILVector2n>;

template class LPPublicKey<ILVector2n>;
template class LPEvalKeyRelin<ILVector2n>;
template class LPEvalKeyNTRURelin<ILVector2n>;
}

