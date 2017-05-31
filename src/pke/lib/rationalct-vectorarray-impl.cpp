/*
 * rationalct-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ciphertext.h"
#include "rationalciphertext.cpp"

namespace lbcrypto {
extern template class CryptoContext<ILDCRT2n>;

template class RationalCiphertext<ILDCRT2n>;
}

