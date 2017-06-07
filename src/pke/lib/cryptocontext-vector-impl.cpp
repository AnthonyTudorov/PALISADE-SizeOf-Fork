/*
 * cryptocontext-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.cpp"

namespace lbcrypto {
template class CryptoContextFactory<ILVector2n>;
template class CryptoContext<ILVector2n>;

template<class ILVector2n> vector<shared_ptr<LPEvalKey<ILVector2n>>> CryptoContext<ILVector2n>::evalMultKeys;
template<class ILVector2n> std::map<usint, shared_ptr<LPEvalKey<ILVector2n>>> CryptoContext<ILVector2n>::evalSumKeys;
}
