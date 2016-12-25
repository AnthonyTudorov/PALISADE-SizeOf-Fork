/*
 * nullscheme-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "nullscheme.h"

namespace lbcrypto {
template class CryptoContext<ILVector2n>;
template class Ciphertext<ILVector2n>;
template class LPCryptoParametersNull<ILVector2n>;
template class LPAlgorithmNull<ILVector2n>;
}
