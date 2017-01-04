/*
 * testJson.h
 *
 *  Created on: May 23, 2016
 *      Author: gerardryan
 */

#ifndef SRC_DEMO_PRE_TESTJSON_H_
#define SRC_DEMO_PRE_TESTJSON_H_

#include <iostream>
#include <fstream>
#include "palisade.h"

#include "encoding/byteplaintextencoding.h"
#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

template<typename Element>
struct TestJsonParms {
	CryptoContext<Element>				ctx;
	shared_ptr<LPPublicKey<Element>>	pk;
	shared_ptr<LPPrivateKey<Element>>	sk;
	shared_ptr<LPEvalKey<Element>>		evalKey;
	shared_ptr<LPPrivateKey<Element>>	newSK;
};

template<typename Element> void testJson(const std::string cID, const BytePlaintextEncoding& newPtxt, TestJsonParms<Element> *p, bool skipReEncrypt = false);

#endif /* SRC_DEMO_PRE_TESTJSON_H_ */
