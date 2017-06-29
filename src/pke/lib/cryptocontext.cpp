/*
 * @file cryptocontext.cpp -- Control for encryption operations.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#include "cryptocontext.h"
#include "utils/serializablehelper.h"

namespace lbcrypto {

template <typename Element>
void CryptoContext<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> key) const {

	if( key == NULL || key->GetCryptoContext() != *this )
		throw std::logic_error("Key passed to EvalMultKeyGen were not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();
	shared_ptr<LPEvalKey<Element>> k = GetEncryptionAlgorithm()->EvalMultKeyGen(key);
	if( evalMultKeys.size() == 0 )
		evalMultKeys.push_back(k);
	else
		evalMultKeys[0] = k;
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMultKeyGen, currentDateTime() - start) );
	}
}

template <typename Element>
void CryptoContext<Element>::ClearEvalMultKeyCache() {
	evalMultKeys.resize(0);
}

template <typename Element>
const shared_ptr<LPEvalKey<Element>> CryptoContext<Element>::GetEvalMultKey() const {
	if( evalMultKeys.size() != 1 )
		throw std::logic_error("You need to use EvalMultKeyGen so that you have an EvalKey available");
	return evalMultKeys[0];
}

template <typename Element>
void CryptoContext<Element>::EvalSumKeyGen(
	const shared_ptr<LPPrivateKey<Element>> privateKey,
	const shared_ptr<LPPublicKey<Element>> publicKey) const {

	//need to add exception handling

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalSumKeyGen(privateKey,publicKey);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumKeyGen, currentDateTime() - start) );
	}
	evalSumKeys = *evalKeys;
}

template <typename Element>
const std::map<usint, shared_ptr<LPEvalKey<Element>>>& CryptoContext<Element>::GetEvalSumKey() const {
	return evalSumKeys;
}

template <typename Element>
shared_ptr<Ciphertext<Element>> CryptoContext<Element>::EvalSum(const shared_ptr<Ciphertext<Element>> ciphertext, usint batchSize) const {

	//need to add exception handling

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalSum(ciphertext, batchSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSum, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Ciphertext<Element>> CryptoContext<Element>::EvalInnerProduct(const shared_ptr<Ciphertext<Element>> ciphertext1, const shared_ptr<Ciphertext<Element>> ciphertext2, usint batchSize) const {

	//need to add exception handling

	auto evalMultKey = GetEvalMultKey();

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalInnerProduct(ciphertext1, ciphertext2, batchSize, evalSumKeys, evalMultKey);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalInnerProduct, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Ciphertext<Element>>
CryptoContext<Element>::EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
		usint indexStart, usint length) const {

	//need to add exception handling

	auto evalMultKey = GetEvalMultKey();

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalCrossCorrelation(x, y, batchSize, indexStart, length, evalSumKeys, evalMultKey);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalCrossCorrelation, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Matrix<RationalCiphertext<Element>>>
CryptoContext<Element>::EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize) const
{
	//need to add exception handling

	auto evalMultKey = GetEvalMultKey();

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalLinRegressBatched(x, y, batchSize, evalSumKeys, evalMultKey);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalLinRegressionBatched, currentDateTime() - start) );
	}
	return rv;
}

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
CryptoContextFactory<T>::genCryptoContextLTV(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersLTV<T>> params(new LPCryptoParametersLTV<T>(
		ep,
		encodingParams,
		stDev,
		assuranceMeasure,
		securityLevel,
		relinWindow,
		depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	return CryptoContext<T>(params, scheme);
}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in LTV context constructor");

	usint depth = numAdds + numMults + numKeyswitches + 1;

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigBinaryInteger(0), BigBinaryInteger(0)) );

	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>() );

	params->SetElementParams(ep);
	params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetAssuranceMeasure(9.0);
	params->SetDepth(depth);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeLTV<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(
	shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
	unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in LTV context constructor");

	usint depth = numAdds + numMults + numKeyswitches + 1;

	shared_ptr<typename T::Params> ep(new typename T::Params(0, BigBinaryInteger::ZERO, BigBinaryInteger::ZERO));

	shared_ptr<LPCryptoParametersLTV<T>> params(new LPCryptoParametersLTV<T>());

	params->SetElementParams(ep);
	params->SetEncodingParams(encodingParams);
	//params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetAssuranceMeasure(9.0);
	params->SetDepth(depth);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextFV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
		const std::string& bigmodulusarb, const std::string& bigrootofunityarb)
{
        bool dbg_flag = false;
	DEBUG("gen 1");
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
					BigBinaryInteger(bigmodulusarb),
					BigBinaryInteger(bigrootofunityarb),
					depth) );
	DEBUG("gen 2");
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );
	DEBUG("gen 3");
	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextFV(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev, const std::string& delta,
	MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
	const std::string& bigmodulusarb, const std::string& bigrootofunityarb)
{
	shared_ptr<LPCryptoParametersFV<T>> params(
		new LPCryptoParametersFV<T>(ep,
			encodingParams,
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			BigBinaryInteger(delta),
			mode,
			BigBinaryInteger(bigmodulus),
			BigBinaryInteger(bigrootofunity),
			BigBinaryInteger(bigmodulusarb),
			BigBinaryInteger(bigrootofunityarb),
			depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeFV<T>());

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

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigBinaryInteger(0), BigBinaryInteger(0)) );

	shared_ptr<LPCryptoParametersFV<T>> params( new LPCryptoParametersFV<T>() );

	params->SetElementParams(ep);
	params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	//params->SetMode(RLWE);
	params->SetMode(OPTIMIZED);
	params->SetAssuranceMeasure(9.0);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextFV(
	shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
	unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in FV context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, BigBinaryInteger::ZERO, BigBinaryInteger::ZERO));

	shared_ptr<LPCryptoParametersFV<T>> params(new LPCryptoParametersFV<T>());

	params->SetElementParams(ep);
	params->SetEncodingParams(encodingParams);
	//params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetMode(OPTIMIZED);
	params->SetAssuranceMeasure(9.0);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeFV<T>());

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
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode, //Mode of noise generation
		depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBV<T>() );

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBV(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev,
	MODE mode, int depth)
{
	shared_ptr<LPCryptoParametersBV<T>> params(new LPCryptoParametersBV<T>(
		ep,
		encodingParams,
		stDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode, //Mode of noise generation
		depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBV<T>());

	return CryptoContext<T>(params, scheme);
}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params( new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			BigBinaryInteger(plaintextmodulus),
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			stDevStSt,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>());

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params(new LPCryptoParametersStehleSteinfeld<T>(
		ep,
		encodingParams,
		stDev,
		assuranceMeasure,
		securityLevel,
		relinWindow,
		stDevStSt,
		depth));

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

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextNull(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams)
{
	shared_ptr<LPCryptoParametersNull<T>> params(new LPCryptoParametersNull<T>(ep, encodingParams));
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeNull<T>());

	return CryptoContext<T>(params, scheme);
}

// the methods below allow me to deserialize a json object into this context
// ... which will only succeed if the object was serialized from this context,
// ... or from another context with identical parameters

template <typename T>
shared_ptr<LPPublicKey<T>>
CryptoContext<T>::deserializePublicKey(const Serialized& serObj) const
{
	if( CryptoContextHelper::matchContextToSerialization(*this, serObj) == false ) {
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
	if( CryptoContextHelper::matchContextToSerialization(*this, serObj) == false ) {
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
	if( CryptoContextHelper::matchContextToSerialization(*this, serObj) == false ) {
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
	if( CryptoContextHelper::matchContextToSerialization(*this, serObj) == false ) {
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
	if( CryptoContextHelper::matchContextToSerialization(*this, serObj) == false ) {
		return shared_ptr<LPEvalKeyNTRURelin<T>>();
	}

	shared_ptr<LPEvalKeyRelin<T>> key( new LPEvalKeyRelin<T>(*this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPEvalKeyRelin<T>>();
}

}

