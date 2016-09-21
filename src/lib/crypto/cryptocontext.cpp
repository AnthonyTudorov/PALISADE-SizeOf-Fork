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

//template <class T, class T2>
//static T* deserializeAndCreate(const std::string& serializedKey, const CryptoContext<T2>* ctx )
//{
//	Serialized ser;
//	if( !SerializableHelper::StringToSerialization(serializedKey, &ser) )
//		return false;
//
//	T *newKey = new T();
//	if( newKey == 0 ) return newKey;
//
//	if( !newKey->Deserialize(ser, ctx) ) {
//		delete newKey;
//		return 0;
//	}
//
//	return newKey;
//}
//
//template <typename T>
//bool CryptoContextImpl<T>::setPublicKey( const std::string& serializedKey )
//{
//	LPPublicKey<T> *newKey = deserializeAndCreate<LPPublicKey<T>,T>(serializedKey, this);
//	if( newKey == 0 ) return false;
//
//	if( publicKey ) delete publicKey;
//	publicKey = newKey;
//	return true;
//}
//
//template <typename T>
//bool CryptoContextImpl<T>::setPrivateKey( const std::string& serializedKey )
//{
//	LPPrivateKey<T> *newKey = deserializeAndCreate<LPPrivateKey<T>,T>(serializedKey, this);
//	if( newKey == 0 ) return false;
//
//	if( privateKey ) delete privateKey;
//	privateKey = newKey;
//	return true;
//}
//
//template <typename T>
//bool CryptoContextImpl<T>::setEvalKey( const std::string& serializedKey )
//{
//	LPEvalKeyRelin<T> *newKey = deserializeAndCreate<LPEvalKeyRelin<T>,T>(serializedKey, this);
//	if( newKey == 0 ) return false;
//
//	if( evalKey ) delete evalKey;
//	evalKey = newKey;
//	return true;
//}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev, int depth)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	shared_ptr<ElemParams> ep( new ILParams(ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

	item.ctx->dgg = DiscreteGaussianGenerator(stDev);				// Create the noise generator

	LPCryptoParametersLTV<T>* params = new LPCryptoParametersLTV<T>(
			ep,
			BigBinaryInteger(plaintextmodulus),
			stDev, // distribution parameter
			0.0, // assuranceMeasure,
			0.0, // securityLevel,
			relinWindow,
			item.ctx->dgg,
			depth);

	item.ctx->params.reset( params );

	item.ctx->scheme = new LPPublicKeyEncryptionSchemeLTV<T>();

	return item;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBV(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	item.ctx->dgg = DiscreteGaussianGenerator(stDev);				// Create the noise generator
	shared_ptr<ElemParams> ep( new ILParams(ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

	LPCryptoParametersBV<T>* params = new LPCryptoParametersBV<T>(
		ep,
		BigBinaryInteger(plaintextmodulus),
		stDev,
		0.0, // assuranceMeasure,
		0.0, // securityLevel,
		relinWindow,
		item.ctx->dgg
		);

	item.ctx->params.reset( params );

	item.ctx->scheme = new LPPublicKeyEncryptionSchemeBV<T>();

	return item;
}

// FIXME: this is temporary until we better incorporate DCRT
template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::getCryptoContextDCRT(LPCryptoParametersLTV<ILVectorArray2n>* cryptoParams)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	item.ctx->params.reset( cryptoParams );
	item.ctx->scheme = new LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n>();

	return item;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev, float stDevStSt)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	shared_ptr<ElemParams> ep( new ILParams(ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

	item.ctx->dgg = DiscreteGaussianGenerator(stDev);				// Create the noise generator
	item.ctx->dggStSt = DiscreteGaussianGenerator(stDevStSt);				// Create the noise generator

	LPCryptoParametersStehleSteinfeld<T>* params = new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			BigBinaryInteger(plaintextmodulus),
			stDev,
			0.0, // assuranceMeasure,
			0.0, // securityLevel,
			relinWindow,
			item.ctx->dgg,
			item.ctx->dggStSt,
			stDevStSt
			);

	item.ctx->params.reset( params );

	item.ctx->scheme = new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>();

	return item;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::getCryptoContextNull(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	shared_ptr<ElemParams> ep( new ILParams(ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

	LPCryptoParametersNull<T>* params = new LPCryptoParametersNull<T>(ep, BigBinaryInteger(plaintextmodulus));

	item.ctx->params.reset( params );

	item.ctx->scheme = new LPPublicKeyEncryptionSchemeNull<T>();

	return item;
}

template <typename T>
shared_ptr<LPPublicKey<T>>
CryptoContext<T>::deserializePublicKey(const Serialized& serObj)
{
	if( CryptoContextHelper<T>::matchContextToSerialization(*this, serObj) == false ) {
		return shared_ptr<LPPublicKey<T>>();
	}

	shared_ptr<LPPublicKey<T>> key( new LPPublicKey<T>(*this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPPublicKey<T>>();
}

template <typename T>
shared_ptr<LPPrivateKey<T>>
CryptoContext<T>::deserializeSecretKey(const Serialized& serObj)
{
	if( CryptoContextHelper<T>::matchContextToSerialization(*this, serObj) == false ) {
		return shared_ptr<LPPrivateKey<T>>();
	}

	shared_ptr<LPPrivateKey<T>> key( new LPPrivateKey<T>(*this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPPrivateKey<T>>();
}

template <typename T>
shared_ptr<Ciphertext<T>>
CryptoContext<T>::deserializeCiphertext(const Serialized& serObj)
{
	if( CryptoContextHelper<T>::matchContextToSerialization(*this, serObj) == false ) {
		return shared_ptr<Ciphertext<T>>();
	}

	shared_ptr<Ciphertext<T>> ctxt( new Ciphertext<T>(*this) );

	if( ctxt->Deserialize(serObj) )
		return ctxt;

	return shared_ptr<Ciphertext<T>>();
}

template <typename T>
shared_ptr<LPEvalKey<T>>
CryptoContext<T>::deserializeEvalKey(const Serialized& serObj)
{
	if( CryptoContextHelper<T>::matchContextToSerialization(*this, serObj) == false ) {
		return shared_ptr<LPEvalKeyNTRURelin<T>>();
	}

	//LPEvalKeyNTRURelin

	shared_ptr<LPEvalKeyNTRURelin<T>> key( new LPEvalKeyNTRURelin<T>(*this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPEvalKeyNTRURelin<T>>();
}

template <typename T>
CryptoContextHandle<T>
CryptoContextFactory<T>::genCryptoContextLTV(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev)
		{
	CryptoContextHandle<T>	item( new CryptoContext<T>() );

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
CryptoContextHandle<T>
CryptoContextFactory<T>::genCryptoContextBV(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev)
		{
			throw std::logic_error("Must implement factory for BV");
		}

// FIXME: this is temporary until we better incorporate DCRT
template <typename T>
CryptoContextHandle<T>
CryptoContextFactory<T>::getCryptoContextDCRT(LPCryptoParametersLTV<ILVectorArray2n>* cryptoParams)
{
	CryptoContextHandle<T>	item( new CryptoContext<T>() );

	item->params = cryptoParams;
	item->algorithm = new LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n>();
	item->algorithm->Enable(ENCRYPTION);
	item->algorithm->Enable(PRE);

	return item;
}

template <typename T>
CryptoContextHandle<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev, float stDevStSt)
		{
	CryptoContextHandle<T>	item( new CryptoContext<T>() );

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

