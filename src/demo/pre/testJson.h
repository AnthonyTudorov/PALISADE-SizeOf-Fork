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
#include "../../lib/crypto/lwecrypt.h"
#include "../../lib/crypto/lwepre.h"
#include "../../lib/lattice/ilvector2n.h"
#include "../../lib/lattice/ilvectorarray2n.h"

#include "../../lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

struct TestJsonParms {
	LPPublicKey<ILVector2n>					*pk;
	LPPublicKey<ILVector2n>					*pkDeserialized;
	LPPrivateKey<ILVector2n>				*sk;
	LPPrivateKey<ILVector2n>				*skDeserialized;
	LPPublicKeyEncryptionScheme<ILVector2n>	*algorithm;
	LPEvalKey<ILVector2n>					*evalKey;
	LPEvalKey<ILVector2n>					*evalKeyDeserialized;
	LPPrivateKey<ILVector2n>				*newSK;
	LPPrivateKey<ILVector2n>				*newSKDeserialized;
	LPCryptoParameters<ILVector2n>			*cryptoParms;
};

extern void testJson(const std::string cID, const ByteArrayPlaintextEncoding& newPtxt, TestJsonParms *p);




#endif /* SRC_DEMO_PRE_TESTJSON_H_ */
