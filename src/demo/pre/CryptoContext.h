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

	CryptoContext() {}

public:
	~CryptoContext() {
		delete params;
		delete algorithm;
	}

	LPCryptoParametersImpl<ILVector2n>* getParams() { return params; }
	LPPublicKeyEncryptionScheme<ILVector2n>* getAlgorithm() { return algorithm; }
	long getChunksize() { return chunksize; }

	usint getPadAmount() { return ringdim/16 * (ptmod.GetMSB()-1); }

	static CryptoContext *genCryptoContextLTV(
			const usint plaintextmodulus,
			usint ringdim, const string& modulus, const string& rootOfUnity,
			usint relinWindow, float stDev) {

		CryptoContext	*item = new CryptoContext();

		item->ringdim = ringdim;
		item->ptmod = BigBinaryInteger(plaintextmodulus);
		item->mod = BigBinaryInteger(modulus);
		item->ru = BigBinaryInteger(rootOfUnity);
		item->relinWindow = relinWindow;
		item->stDev = stDev;

		item->ilParams = ILParams(item->ringdim, item->mod, item->ru);

		LPCryptoParametersLTV<ILVector2n>* params = new LPCryptoParametersLTV<ILVector2n>();
		item->params = params;

		params->SetPlaintextModulus(item->ptmod);
		params->SetDistributionParameter(item->stDev);
		params->SetRelinWindow(item->relinWindow);
		params->SetElementParams(item->ilParams);

		item->dgg = DiscreteGaussianGenerator(stDev);				// Create the noise generator
		params->SetDiscreteGaussianGenerator(item->dgg);

		item->chunksize = ((item->ringdim / 2) / 8) * log2(plaintextmodulus);

		item->algorithm = new LPPublicKeyEncryptionSchemeLTV<ILVector2n>();
		item->algorithm->Enable(ENCRYPTION);
		item->algorithm->Enable(PRE);

		return item;
	}

	static CryptoContext *genCryptoContextStehleSteinfeld(
			const usint plaintextmodulus,
			usint ringdim, const string& modulus, const string& rootOfUnity,
			usint relinWindow, float stDev, float stDevStSt) {

		CryptoContext	*item = new CryptoContext();

		item->ringdim = ringdim;
		item->ptmod = BigBinaryInteger(plaintextmodulus);
		item->mod = BigBinaryInteger(modulus);
		item->ru = BigBinaryInteger(rootOfUnity);
		item->relinWindow = relinWindow;
		item->stDev = stDev;
		item->stDevStSt = stDevStSt;

		item->ilParams = ILParams(item->ringdim, item->mod, item->ru);

		LPCryptoParametersStehleSteinfeld<ILVector2n>* params = new LPCryptoParametersStehleSteinfeld<ILVector2n>();
		item->params = params;

		params->SetPlaintextModulus(item->ptmod);
		params->SetDistributionParameter(item->stDev);
		params->SetDistributionParameterStSt(item->stDevStSt);
		params->SetRelinWindow(item->relinWindow);
		params->SetElementParams(item->ilParams);

		item->dgg = DiscreteGaussianGenerator(stDev);				// Create the noise generator
		params->SetDiscreteGaussianGenerator(item->dgg);

		item->dggStSt = DiscreteGaussianGenerator(stDevStSt);				// Create the noise generator
		params->SetDiscreteGaussianGeneratorStSt(item->dggStSt);

		item->chunksize = ((item->ringdim / 2) / 8) * log2(plaintextmodulus);

		item->algorithm = new LPPublicKeyEncryptionSchemeStehleSteinfeld<ILVector2n>();
		item->algorithm->Enable(ENCRYPTION);
		item->algorithm->Enable(PRE);

		return item;
	}
};



#endif /* SRC_DEMO_PRE_CRYPTOCONTEXT_H_ */
