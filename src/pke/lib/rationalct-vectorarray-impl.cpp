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
extern template class CryptoContext<ILVectorArray2n>;

template class RationalCiphertext<ILVectorArray2n>;
}

