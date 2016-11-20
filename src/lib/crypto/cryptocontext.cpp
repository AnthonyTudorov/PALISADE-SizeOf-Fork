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

/**
 * Serialize the context (it's really just the params...)
 *
 * @param serObj
 * @param fileFlag
 * @return
 */
template <typename T>
bool
CryptoContextImpl<T>::Serialize(Serialized* serObj) const
{
	return params->Serialize(serObj);
}

/**
 * Deserialize the context AND initialize the algorithm
 *
 * @param serObj
 * @return
 */
template <typename T>
bool
CryptoContext<T>::Deserialize(const Serialized& serObj)
{
	CryptoContext<T> newctx = CryptoContextFactory<T>::DeserializeAndCreateContext(serObj);

	if( newctx.ctx ) {
		this->ctx = newctx.ctx;
		return true;
	}

	return false;
}

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

	LPCryptoParametersLTV<T>* params = new LPCryptoParametersLTV<T>(
			ep,
			BigBinaryInteger(plaintextmodulus),
			stDev, // distribution parameter
			0.0, // assuranceMeasure,
			0.0, // securityLevel,
			relinWindow,
			depth);

	item.ctx->params.reset( params );
	item.ctx->scheme.reset(new LPPublicKeyEncryptionSchemeLTV<T>());

	return item;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextFV(
		const usint plaintextmodulus,
		usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	shared_ptr<ElemParams> ep( new ILParams(ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

	LPCryptoParametersFV<T>* params =
			new LPCryptoParametersFV<T>(ep,
					BigBinaryInteger(plaintextmodulus),
					stDev,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					BigBinaryInteger(delta),
					mode,
					BigBinaryInteger(bigmodulus),
					BigBinaryInteger(bigrootofunity),
					depth);

	item.ctx->params.reset( params );
	item.ctx->scheme.reset( new LPPublicKeyEncryptionSchemeFV<T>() );

	return item;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextFV(
		const BigBinaryInteger& plaintextModulus, float securityLevel,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in FV context constructor");

	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	shared_ptr<ElemParams> ep( new ILParams(0, BigBinaryInteger::ZERO, BigBinaryInteger::ZERO) );

	LPCryptoParametersFV<T>* params = new LPCryptoParametersFV<T>();

	params->SetElementParams(ep);
	params->SetPlaintextModulus(plaintextModulus);
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(16);
	params->SetDistributionParameter(4.0);
	params->SetMode(OPTIMIZED);
	params->SetAssuranceMeasure(9.0);

	item.ctx->params.reset( params );
	item.ctx->scheme.reset( new LPPublicKeyEncryptionSchemeFV<T>() );

	item.ctx->scheme->ParamsGen(item.GetCryptoParameters(), numAdds, numMults, numKeyswitches);

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

	shared_ptr<ElemParams> ep( new ILParams(ringdim, BigBinaryInteger(modulus), BigBinaryInteger(rootOfUnity)) );

	LPCryptoParametersBV<T>* params = new LPCryptoParametersBV<T>(
		ep,
		BigBinaryInteger(plaintextmodulus),
		stDev,
		0.0, // assuranceMeasure,
		0.0, // securityLevel,
		relinWindow
		);

	item.ctx->params.reset( params );
	item.ctx->scheme.reset( new LPPublicKeyEncryptionSchemeBV<T>() );

	return item;
}

// FIXME: this is temporary until we better incorporate DCRT
template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::getCryptoContextDCRT(LPCryptoParametersLTV<ILVectorArray2n>* cryptoParams)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	LPCryptoParametersLTV<ILVectorArray2n>* mycryptoParams = new LPCryptoParametersLTV<ILVectorArray2n>( *cryptoParams); // copy so memory works right

	item.ctx->params.reset( mycryptoParams );
	item.ctx->scheme.reset( new LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n>() );

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

	LPCryptoParametersStehleSteinfeld<T>* params = new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			BigBinaryInteger(plaintextmodulus),
			stDev,
			0.0, // assuranceMeasure,
			0.0, // securityLevel,
			relinWindow,
			stDevStSt
			);

	item.ctx->params.reset( params );
	item.ctx->scheme.reset( new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>() );

	return item;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::getCryptoContextNull(
		const usint modulus,
		usint ringdim)
{
	CryptoContext<T>	item( new CryptoContextImpl<T>() );

	shared_ptr<ElemParams> ep( new ILParams(ringdim, BigBinaryInteger(modulus), BigBinaryInteger::ONE) );

	LPCryptoParametersNull<T>* params = new LPCryptoParametersNull<T>(ep, BigBinaryInteger(modulus));

	item.ctx->params.reset( params );
	item.ctx->scheme.reset( new LPPublicKeyEncryptionSchemeNull<T>() );

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
shared_ptr<LPEvalKey<T>>
CryptoContext<T>::deserializeEvalMultKey(const Serialized& serObj)
{
	if( CryptoContextHelper<T>::matchContextToSerialization(*this, serObj) == false ) {
		return shared_ptr<LPEvalKeyNTRURelin<T>>();
	}

	shared_ptr<LPEvalKeyRelin<T>> key( new LPEvalKeyRelin<T>(*this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPEvalKeyRelin<T>>();
}
}

