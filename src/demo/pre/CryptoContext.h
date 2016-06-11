/*
 * CryptoContext.h
 *
 *  Created on: May 27, 2016
 *      Author: gwryan
 */

#ifndef SRC_DEMO_PRE_CRYPTOCONTEXT_H_
#define SRC_DEMO_PRE_CRYPTOCONTEXT_H_

#include <string>

#include "math/backend.h"
#include "utils/inttypes.h"

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"

#include "crypto/lwecrypt.h"
#include "crypto/lwecrypt.cpp"
#include "crypto/lwepre.h"
#include "crypto/lwepre.cpp"
#include "crypto/lweahe.h"
#include "crypto/lweahe.cpp"
#include "crypto/lweshe.h"
#include "crypto/lweshe.cpp"
#include "crypto/lwefhe.h"
#include "crypto/lwefhe.cpp"
#include "crypto/lweautomorph.h"
#include "crypto/lweautomorph.cpp"


#include "crypto/ciphertext.h"
#include "crypto/ciphertext.cpp"

using namespace std;
using namespace lbcrypto;

namespace lbcrypto {

class CryptoContext {
private:
	usint ringdim;
	BigBinaryInteger ptmod;
	BigBinaryInteger mod;
	BigBinaryInteger ru;
	usint relinWindow;
	float stDev;
	float stDevStSt;

	ILParams ilParams;
	DiscreteGaussianGenerator dgg;
	DiscreteGaussianGenerator dggStSt;

	LPCryptoParametersImpl<ILVector2n>	*params;
	LPPublicKeyEncryptionScheme<ILVector2n> *algorithm;
	long								chunksize;

	// these three are used by the wrapper to cache deserialized keys
	LPPublicKeyLTV<ILVector2n>	*publicKey;
	LPPrivateKeyLTV<ILVector2n>	*privateKey;
	LPEvalKeyLTV<ILVector2n>	*evalKey;

	CryptoContext() : publicKey(0), privateKey(0), evalKey(0) {}

public:
	~CryptoContext() {
		delete params;
		delete algorithm;
		if( publicKey ) delete publicKey;
		if( privateKey ) delete privateKey;
		if( evalKey ) delete evalKey;
	}

	LPCryptoParametersImpl<ILVector2n>* getParams() { return params; }
	LPPublicKeyEncryptionScheme<ILVector2n>* getAlgorithm() { return algorithm; }
	long getChunksize() { return chunksize; }

	usint getPadAmount() { return ringdim/16 * (ptmod.GetMSB()-1); }

	bool setPublicKey( const string& serializedKey );
	LPPublicKeyLTV<ILVector2n>	*getPublicKey() { return publicKey; }
	bool setPrivateKey( const string& serializedKey );
	LPPrivateKeyLTV<ILVector2n>	*getPrivateKey() { return privateKey; }
	bool setEvalKey( const string& serializedKey );
	LPEvalKeyLTV<ILVector2n>	*getEvalKey() { return evalKey; }

	static CryptoContext *genCryptoContextLTV(
			const usint plaintextmodulus,
			usint ringdim, const string& modulus, const string& rootOfUnity,
			usint relinWindow, float stDev);

	static CryptoContext *genCryptoContextStehleSteinfeld(
			const usint plaintextmodulus,
			usint ringdim, const string& modulus, const string& rootOfUnity,
			usint relinWindow, float stDev, float stDevStSt);
};

}


#endif /* SRC_DEMO_PRE_CRYPTOCONTEXT_H_ */
