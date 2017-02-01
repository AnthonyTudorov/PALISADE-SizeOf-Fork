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
template class CryptoContextFactory<ILVectorArray2n>;
template class CryptoContext<ILVectorArray2n>;
template class CryptoContextHelper<ILVectorArray2n>;
}

