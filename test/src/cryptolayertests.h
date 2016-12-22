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

class Plaintext;
}

using namespace lbcrypto;

template <class Element, class Ptxt>
void UnitTestEncryption(const CryptoContext<Element>& cc, const Ptxt& plaintext);

#endif /* TEST_SRC_CRYPTOLAYERTESTS_H_ */
