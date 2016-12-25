/*
 * ciphertext-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ciphertext.h"

namespace lbcrypto {
extern template class CryptoContext<ILVector2n>;

template class Ciphertext<ILVector2n>;
}

