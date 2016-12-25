/*
 * ltv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ltv.h"

namespace lbcrypto {
template class CryptoContext<ILVector2n>;
template class Ciphertext<ILVector2n>;
template class LPCryptoParametersLTV<ILVector2n>;
template class LPAlgorithmLTV<ILVector2n>;
}
