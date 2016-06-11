/*
 * CryptoContext.cpp
 *
 *  Created on: Jun 11, 2016
 *      Author: gerardryan
 */

#include "CryptoContext.h"
#include "utils/serializablehelper.h"

namespace lbcrypto {

// these three functions are essentially identical and ought to be refactored...
bool
CryptoContext::setPublicKey( const string& serializedKey )
{
	Serialized ser;
	if( !SerializableHelper::StringToSerialization(serializedKey, &ser) )
		return false;

	LPPublicKeyLTV<ILVector2n> *newKey = new LPPublicKeyLTV<ILVector2n>();
	if( newKey == 0 ) return false;

	if( !newKey->Deserialize(ser) ) {
		delete newKey;
		return false;
	}

	if( publicKey ) delete publicKey;
	publicKey = newKey;
	return true;
}

bool
CryptoContext::setPrivateKey( const string& serializedKey )
{
	Serialized ser;
	if( !SerializableHelper::StringToSerialization(serializedKey, &ser) )
		return false;

	LPPrivateKeyLTV<ILVector2n> *newKey = new LPPrivateKeyLTV<ILVector2n>();
	if( newKey == 0 ) return false;

	if( !newKey->Deserialize(ser) ) {
		delete newKey;
		return false;
	}

	if( privateKey ) delete privateKey;
	privateKey = newKey;
	return true;
}

bool CryptoContext::setEvalKey( const string& serializedKey )
{
	Serialized ser;
	if( !SerializableHelper::StringToSerialization(serializedKey, &ser) )
		return false;

	LPEvalKeyLTV<ILVector2n> *newKey = new LPEvalKeyLTV<ILVector2n>();
	if( newKey == 0 ) return false;

	if( !newKey->Deserialize(ser) ) {
		delete newKey;
		return false;
	}

	if( evalKey ) delete evalKey;
	evalKey = newKey;
	return true;
}

CryptoContext *
CryptoContext::genCryptoContextLTV(
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

CryptoContext *
CryptoContext::genCryptoContextStehleSteinfeld(
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

}

