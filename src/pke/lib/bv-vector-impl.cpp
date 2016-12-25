/*
 * bv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "bv.cpp"

namespace lbcrypto {
template class CryptoContext<ILVector2n>;
template class Ciphertext<ILVector2n>;
template class LPCryptoParametersBV<ILVector2n>;
template class LPAlgorithmBV<ILVector2n>;
}
