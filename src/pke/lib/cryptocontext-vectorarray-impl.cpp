/*
 * cryptocontext-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.cpp"

namespace lbcrypto {
template class CryptoContextFactory<ILVectorArray2n>;
template class CryptoContext<ILVectorArray2n>;

template<class ILVectorArray2n> vector<shared_ptr<LPEvalKey<ILVectorArray2n>>> CryptoContext<ILVectorArray2n>::evalMultKeys;
}

