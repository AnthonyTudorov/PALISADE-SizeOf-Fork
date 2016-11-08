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
#include "../../lib/math/backend.h"
#include "../../lib/utils/inttypes.h"
#include "../../lib/math/nbtheory.h"
#include "../../lib/lattice/elemparams.h"
#include "../../lib/lattice/ilparams.h"
#include "../../lib/lattice/ildcrtparams.h"
#include "../../lib/lattice/ilelement.h"
#include "../../lib/math/distrgen.h"
#include "../../lib/lattice/ilvector2n.h"
#include "../../lib/lattice/ilvectorarray2n.h"

#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/utils/debug.h"

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
