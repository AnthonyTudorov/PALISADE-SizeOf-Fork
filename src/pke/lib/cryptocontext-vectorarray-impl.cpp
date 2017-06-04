/*
 * cryptocontext-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.cpp"

namespace lbcrypto {
template class CryptoContextFactory<ILDCRT2n>;
template class CryptoContext<ILDCRT2n>;

template<class ILDCRT2n> vector<shared_ptr<LPEvalKey<ILDCRT2n>>> CryptoContext<ILDCRT2n>::evalMultKeys;
}

