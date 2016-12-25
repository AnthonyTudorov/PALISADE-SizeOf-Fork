/*
 * fv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "fv.cpp"

namespace lbcrypto {
template class CryptoContext<ILVector2n>;
template class Ciphertext<ILVector2n>;
template class LPCryptoParametersFV<ILVector2n>;
template class LPAlgorithmFV<ILVector2n>;
}
