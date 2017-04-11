/**
* @file		cryptocontext.cpp
*
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

#include "cryptocontext.h"
#include "utils/serializablehelper.h"

namespace lbcrypto {

template <typename T>
bool
CryptoContext<T>::Deserialize(const Serialized& serObj)
{
	CryptoContext<T> newctx = CryptoContextFactory<T>::DeserializeAndCreateContext(serObj);

	if( newctx ) {
		*this = newctx;
		return true;
	}

	return false;
}

// factory methods for the different schemes

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>(
			ep,
			BigBinaryInteger(plaintextmodulus),
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextFV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersFV<T>> params(
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
					depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextFV(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in FV context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigBinaryInteger::ZERO, BigBinaryInteger::ZERO) );

	shared_ptr<LPCryptoParametersFV<T>> params( new LPCryptoParametersFV<T>() );

	params->SetElementParams(ep);
	params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetMode(OPTIMIZED);
	params->SetAssuranceMeasure(9.0);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContext<T>(params, scheme);
}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode, int depth)
{
	shared_ptr<LPCryptoParametersBV<T>> params( new LPCryptoParametersBV<T>(
		ep,
		BigBinaryInteger(plaintextmodulus),
		stDev,
		0.0, // assuranceMeasure,
		0.0, // securityLevel,
		relinWindow, // Relinearization Window
		mode, //Mode of noise generation
		depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBV<T>() );

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt)
{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params( new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			BigBinaryInteger(plaintextmodulus),
			stDev,
			0.0, // assuranceMeasure,
			0.0, // securityLevel,
			relinWindow,
			stDevStSt) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>());

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextNull(shared_ptr<typename T::Params> ep,
		const usint ptModulus)
{
	shared_ptr<LPCryptoParametersNull<T>> params( new LPCryptoParametersNull<T>(ep, BigBinaryInteger(ptModulus)) );
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeNull<T>() );

	return CryptoContext<T>(params, scheme);
}

// the methods below allow me to deserialize a json object into this context
// ... which will only succeed if the object was serialized from this context,
// ... or from another context with identical parameters

template <typename T>
shared_ptr<LPPublicKey<T>>
CryptoContext<T>::deserializePublicKey(const Serialized& serObj) const
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
CryptoContext<T>::deserializeSecretKey(const Serialized& serObj) const
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
CryptoContext<T>::deserializeCiphertext(const Serialized& serObj) const
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
CryptoContext<T>::deserializeEvalKey(const Serialized& serObj) const
{
	if( CryptoContextHelper<T>::matchContextToSerialization(*this, serObj) == false ) {
		return shared_ptr<LPEvalKeyNTRURelin<T>>();
	}

	shared_ptr<LPEvalKeyNTRURelin<T>> key( new LPEvalKeyNTRURelin<T>(*this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPEvalKeyNTRURelin<T>>();
}


template <typename T>
shared_ptr<LPEvalKey<T>>
CryptoContext<T>::deserializeEvalMultKey(const Serialized& serObj) const
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

