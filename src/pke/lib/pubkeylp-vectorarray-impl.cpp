/*
 * pubkeylp-vector-impl.cpp
 *
 *  Created on: May 22, 2017
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "pubkeylp.cpp"

namespace lbcrypto {
extern template class CryptoContext<ILDCRT2n>;

template class LPPublicKey<ILDCRT2n>;
template class LPEvalKeyRelin<ILDCRT2n>;
template class LPEvalKeyNTRURelin<ILDCRT2n>;
}

