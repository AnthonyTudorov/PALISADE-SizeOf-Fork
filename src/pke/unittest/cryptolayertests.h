/*
 * cryptolayertests.h
 *
 *  Created on: Dec 22, 2016
 *      Author: gerardryan
 */

#ifndef TEST_SRC_CRYPTOLAYERTESTS_H_
#define TEST_SRC_CRYPTOLAYERTESTS_H_

namespace lbcrypto {
template <class Element> class CryptoContext;

}

using namespace lbcrypto;

template <class Element>
void UnitTestEncryption(const CryptoContext<Element>& cc);

template <class Element>
void UnitTestReEncryption(const CryptoContext<Element>& cc);

#endif /* TEST_SRC_CRYPTOLAYERTESTS_H_ */
