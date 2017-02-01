/*
 * cryptocontext-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.cpp"
#include "cryptocontexthelper.cpp"
#include "math/matrix.cpp"

namespace lbcrypto {
template class CryptoContextFactory<ILVector2n>;
template class CryptoContext<ILVector2n>;
template class CryptoContextHelper<ILVector2n>;
}
