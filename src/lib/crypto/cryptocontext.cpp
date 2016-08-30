/**
* @file
* @author	TPOC:
				Dr. Kurt Rohloff <rohloff@njit.edu>,
			Programmers:
				Jerry Ryan <gwryan@njit.edu>

* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
* OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* @section DESCRIPTION
*
* This file implements the Crypto Context: all the pieces needed to use the palisade library
*/

#include "../crypto/cryptocontext.h"
#include "../utils/serializablehelper.h"

namespace lbcrypto {

template <class T, class T2>
static T* deserializeAndCreate(const std::string& serializedKey, const CryptoContext<T2>* ctx )
{
	Serialized ser;
	if( !SerializableHelper::StringToSerialization(serializedKey, &ser) )
		return false;

	T *newKey = new T();
	if( newKey == 0 ) return newKey;

	if( !newKey->Deserialize(ser, ctx) ) {
		delete newKey;
		return 0;
	}

	return newKey;
}

template <typename T>
bool CryptoContext<T>::setPublicKey( const std::string& serializedKey )
{
	LPPublicKey<T> *newKey = deserializeAndCreate<LPPublicKey<T>,T>(serializedKey, this);
	if( newKey == 0 ) return false;

	if( publicKey ) delete publicKey;
	publicKey = newKey;
	return true;
}

template <typename T>
bool CryptoContext<T>::setPrivateKey( const std::string& serializedKey )
{
	LPPrivateKey<T> *newKey = deserializeAndCreate<LPPrivateKey<T>,T>(serializedKey, this);
	if( newKey == 0 ) return false;

	if( privateKey ) delete privateKey;
	privateKey = newKey;
	return true;
}

template <typename T>
bool CryptoContext<T>::setEvalKey( const std::string& serializedKey )
{
	LPEvalKeyRelin<T> *newKey = deserializeAndCreate<LPEvalKeyRelin<T>,T>(serializedKey, this);
	if( newKey == 0 ) return false;

	if( evalKey ) delete evalKey;
	evalKey = newKey;
	return true;
}

template <typename T>
CryptoContext<T> *CryptoContext<T>::genCryptoContextLTV(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev) {

	CryptoContext	*item = new CryptoContext();

	item->ringdim = ringdim;
	item->ptmod = BigBinaryInteger(plaintextmodulus);
	item->mod = BigBinaryInteger(modulus);
	item->ru = BigBinaryInteger(rootOfUnity);
	item->relinWindow = relinWindow;
	item->stDev = stDev;

	item->ilParams = ILParams(item->ringdim, item->mod, item->ru);

	LPCryptoParametersLTV<T>* params = new LPCryptoParametersLTV<T>();
	item->params = params;

	params->SetPlaintextModulus(item->ptmod);
	params->SetDistributionParameter(item->stDev);
	params->SetRelinWindow(item->relinWindow);
	params->SetElementParams(item->ilParams);

	item->dgg = DiscreteGaussianGenerator(stDev);				// Create the noise generator
	params->SetDiscreteGaussianGenerator(item->dgg);

	item->algorithm = new LPPublicKeyEncryptionSchemeLTV<T>();
	item->algorithm->Enable(ENCRYPTION);
	item->algorithm->Enable(PRE);

	return item;
}

template <typename T>
CryptoContext<T> *CryptoContext<T>::getCryptoContextDCRT(LPCryptoParametersLTV<ILVectorArray2n>* params) {
	CryptoContext	*item = new CryptoContext();

	item->params = params;
	item->algorithm = new LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n>();
	item->algorithm->Enable(ENCRYPTION);
	item->algorithm->Enable(PRE);

	return item;
}


template <typename T>
CryptoContext<T> *CryptoContext<T>::genCryptoContextStehleSteinfeld(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
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

	LPCryptoParametersStehleSteinfeld<T>* params = new LPCryptoParametersStehleSteinfeld<T>();
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

	item->algorithm = new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>();
	item->algorithm->Enable(ENCRYPTION);
	item->algorithm->Enable(PRE);

	return item;
}

}

