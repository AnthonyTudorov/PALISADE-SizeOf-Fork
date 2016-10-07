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

	item.ctx->ringdim = ringdim;

	shared_ptr<ElemParams> ep( new ILParams(item.ctx->ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

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

	item.ctx->ringdim = ringdim;

	item.ctx->dgg = DiscreteGaussianGenerator(stDev);				// Create the noise generator
	shared_ptr<ElemParams> ep( new ILParams(item.ctx->ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

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

	item.ctx->ringdim = ringdim;

	shared_ptr<ElemParams> ep( new ILParams(item.ctx->ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

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
CryptoContextFactory<T>::getCryptoContextNull()
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	item.ctx->ringdim = 4096;

	shared_ptr<ElemParams> ep( new ILParams(item.ctx->ringdim, BigBinaryInteger::ONE, BigBinaryInteger::ONE) );

	LPCryptoParametersNull<T>* params = new LPCryptoParametersNull<T>(ep, BigBinaryInteger::TWO);

	item.ctx->params.reset( params );

	item.ctx->scheme = new LPPublicKeyEncryptionSchemeNull<T>();

	return item;
}

}

