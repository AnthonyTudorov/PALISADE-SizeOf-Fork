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

namespace lbcrypto {

template <typename Element>
std::map<string,std::vector<LPEvalKey<Element>>>					CryptoContextImpl<Element>::evalMultKeyMap;

template <typename Element>
std::map<string,shared_ptr<std::map<usint,LPEvalKey<Element>>>>	CryptoContextImpl<Element>::evalSumKeyMap;

template <typename Element>
std::map<string,shared_ptr<std::map<usint,LPEvalKey<Element>>>>	CryptoContextImpl<Element>::evalAutomorphismKeyMap;

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeyGen(const LPPrivateKey<Element> key) {

	if( key == NULL || Mismatched(key->GetCryptoContext()) )
		throw std::logic_error("Key passed to EvalMultKeyGen were not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();

	LPEvalKey<Element> k = GetEncryptionAlgorithm()->EvalMultKeyGen(key);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMultKeyGen, currentDateTime() - start) );
	}

	evalMultKeyMap[ k->GetKeyTag() ] = { k };
}

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeysGen(const LPPrivateKey<Element> key) {

	if( key == NULL || Mismatched(key->GetCryptoContext()) )
		throw std::logic_error("Key passed to EvalMultsKeyGen were not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();

	const vector<LPEvalKey<Element>> &evalKeys = GetEncryptionAlgorithm()->EvalMultKeysGen(key);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMultKeyGen, currentDateTime() - start) );
	}

	evalMultKeyMap[ evalKeys[0]->GetKeyTag() ] = evalKeys;
}

template <typename Element>
const vector<LPEvalKey<Element>>& CryptoContextImpl<Element>::GetEvalMultKeyVector(const string& keyID) {
	auto ekv = evalMultKeyMap.find(keyID);
	if( ekv == evalMultKeyMap.end() )
		throw std::logic_error("You need to use EvalMultKeyGen so that you have an EvalMultKey available for this ID");
	return ekv->second;
}

template <typename Element>
const std::map<string,std::vector<LPEvalKey<Element>>>& CryptoContextImpl<Element>::GetAllEvalMultKeys() {
	return evalMultKeyMap;
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys() {
	evalMultKeyMap.clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const string& id) {
	auto kd = evalMultKeyMap.find(id);
	if( kd != evalMultKeyMap.end() )
		evalMultKeyMap.erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const CryptoContext<Element> cc) {
	for( auto it = evalMultKeyMap.begin(); it != evalMultKeyMap.end(); ) {
		if( it->second[0]->GetCryptoContext() == cc ) {
			it = evalMultKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalMultKey(const std::vector<LPEvalKey<Element>>& vectorToInsert) {
	evalMultKeyMap[ vectorToInsert[0]->GetKeyTag() ] = vectorToInsert;
}

template <typename Element>
void CryptoContextImpl<Element>::EvalSumKeyGen(
		const LPPrivateKey<Element> privateKey,
		const LPPublicKey<Element> publicKey) {

	if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) ) {
		throw std::logic_error("Private key passed to EvalSumKeyGen were not generated with this crypto context");
	}

	if( publicKey != NULL && privateKey->GetKeyTag() != publicKey->GetKeyTag() ) {
		throw std::logic_error("Public key passed to EvalSumKeyGen does not match private key");
	}

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalSumKeyGen(privateKey,publicKey);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumKeyGen, currentDateTime() - start) );
	}
	evalSumKeyMap[privateKey->GetKeyTag()] = evalKeys;
}

template <typename Element>
const std::map<usint, LPEvalKey<Element>>& CryptoContextImpl<Element>::GetEvalSumKeyMap(const string& keyID) {
	auto ekv = evalSumKeyMap.find(keyID);
	if( ekv == evalSumKeyMap.end() )
		throw std::logic_error("You need to use EvalSumKeyGen so that you have EvalSumKeys available for this ID");
	return *ekv->second;
}

template <typename Element>
const std::map<string,shared_ptr<std::map<usint, LPEvalKey<Element>>>>& CryptoContextImpl<Element>::GetAllEvalSumKeys() {
	return evalSumKeyMap;
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys() {
	evalSumKeyMap.clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const string& id) {
	auto kd = evalSumKeyMap.find(id);
	if( kd != evalSumKeyMap.end() )
		evalSumKeyMap.erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const CryptoContext<Element> cc) {
	for( auto it = evalSumKeyMap.begin(); it != evalSumKeyMap.end(); ) {
		if( it->second->begin()->second->GetCryptoContext() == cc ) {
			it = evalSumKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalSumKey(const shared_ptr<std::map<usint,LPEvalKey<Element>>> mapToInsert) {
	// find the tag
	auto onekey = mapToInsert->begin();
	evalSumKeyMap[ onekey->second->GetKeyTag() ] = mapToInsert;
}

template <typename Element>
void CryptoContextImpl<Element>::EvalAtIndexKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<int32_t> &indexList, const LPPublicKey<Element> publicKey) {

	if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) ) {
		throw std::logic_error("Private key passed to EvalAtIndexKeyGen were not generated with this crypto context");
	}

	if( publicKey != NULL && privateKey->GetKeyTag() != publicKey->GetKeyTag() ) {
		throw std::logic_error("Public key passed to EvalAtIndexKeyGen does not match private key");
	}

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalAtIndexKeyGen(publicKey,privateKey,indexList);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalAtIndexKeyGen, currentDateTime() - start) );
	}

	evalAutomorphismKeyMap[privateKey->GetKeyTag()] = evalKeys;
}

template <typename Element>
const std::map<usint, LPEvalKey<Element>>& CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(const string& keyID) {
	auto ekv = evalAutomorphismKeyMap.find(keyID);
	if( ekv == evalAutomorphismKeyMap.end() )
		throw std::logic_error("You need to use EvalAutomorphismKeyGen so that you have EvalAutomorphismKeys available for this ID");
	return *ekv->second;
}

template <typename Element>
const std::map<string,shared_ptr<std::map<usint, LPEvalKey<Element>>>>& CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys() {
	return evalAutomorphismKeyMap;
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys() {
	evalAutomorphismKeyMap.clear();
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const string& id) {
	auto kd = evalAutomorphismKeyMap.find(id);
	if( kd != evalAutomorphismKeyMap.end() )
		evalAutomorphismKeyMap.erase(kd);
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const CryptoContext<Element> cc) {
	for( auto it = evalAutomorphismKeyMap.begin(); it != evalAutomorphismKeyMap.end(); ) {
		if( it->second->begin()->second->GetCryptoContext() == cc ) {
			it = evalAutomorphismKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalAutomorphismKey(const shared_ptr<std::map<usint,LPEvalKey<Element>>> mapToInsert) {
	// find the tag
	auto onekey = mapToInsert->begin();
	evalAutomorphismKeyMap[ onekey->second->GetKeyTag() ] = mapToInsert;
}

/**
 * SerializeEvalMultKey for a single EvalMult key
 */
template <typename Element>
bool CryptoContextImpl<Element>::SerializeEvalMultKey(std::ostream& ser, Serializable::Type sertype, const string id) {
	decltype(evalMultKeyMap)	*smap;
	decltype(evalMultKeyMap)	omap;

	if( id.length() == 0 )
		smap = &evalMultKeyMap;
	else {
		auto k = evalMultKeyMap.find(id);

		if( k == evalMultKeyMap.end() )
			return false; // no such id

		smap = &omap;
		omap[ k->first ] = k->second;
	}
	Serializable::Serialize(*smap, ser, sertype);
	return true;
}

/**
 * SerializeEvalMultKey for all EvalMultKeys made in a given context
 * method will serialize the context only once
 */
template <typename Element>
bool CryptoContextImpl<Element>::SerializeEvalMultKey(std::ostream& ser, Serializable::Type sertype, const CryptoContext<Element> cc) {

	decltype(evalMultKeyMap) omap;
	for( const auto& k : evalMultKeyMap ) {
		if( k.second[0]->GetCryptoContext() == cc ) {
			omap[k.first] = k.second;
		}
	}

	if( omap.size() == 0 )
		return false;

	Serializable::Serialize(omap, ser, sertype);
	return true;
}

template <typename Element>
bool CryptoContextImpl<Element>::DeserializeEvalMultKey(std::istream& ser, Serializable::Type sertype) {

	decltype(evalMultKeyMap) evalMultKeys;

	Serializable::Deserialize(evalMultKeys, ser, sertype);

	// The deserialize call created any contexts that needed to be created.... so all we need to do
	// is put the keys into the maps for their context

	for( auto k : evalMultKeys ) {

		evalMultKeyMap[ k.first ] = k.second;
	}

	return true;
}

/**
 * SerializeEvalSumKey for all EvalSum keys
 */
template <typename Element>
bool CryptoContextImpl<Element>::SerializeEvalSumKey(std::ostream& ser, Serializable::Type sertype, string id) {
	decltype(evalSumKeyMap)*	smap;
	decltype(evalSumKeyMap)		omap;
	if( id.length() == 0 )
		smap = &evalSumKeyMap;
	else {
		auto k = evalSumKeyMap.find(id);

		if( k == evalSumKeyMap.end() )
			return false; // no such id

		smap = &omap;
		omap[ k->first ] = k->second;
	}
	Serializable::Serialize(*smap, ser, sertype);
	return true;
}

/**
 * SerializeEvalSumKey for all EvalSumKeys made in a given context
 * method will serialize the context only once
 */
template <typename Element>
bool CryptoContextImpl<Element>::SerializeEvalSumKey(std::ostream& ser, Serializable::Type sertype, const CryptoContext<Element> cc) {

	decltype(evalSumKeyMap) omap;
	for( const auto& k : evalSumKeyMap ) {
		if( k.second->begin()->second->GetCryptoContext() == cc ) {
			omap[k.first] = k.second;
		}
	}

	if( omap.size() == 0 )
		return false;

	Serializable::Serialize(omap, ser, sertype);
	return true;
}

template <typename Element>
bool CryptoContextImpl<Element>::DeserializeEvalSumKey(std::istream& ser, Serializable::Type sertype) {

	decltype(evalSumKeyMap) evalSumKeys;

	Serializable::Deserialize(evalSumKeys, ser, sertype);

	// The deserialize call created any contexts that needed to be created.... so all we need to do
	// is put the keys into the maps for their context

	for( auto k : evalSumKeys ) {
		evalSumKeyMap[ k.first ] = k.second;
	}

	return true;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize) const {

	if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
		throw std::logic_error("Information passed to EvalSum was not generated with this crypto context");

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());
	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalSum(ciphertext, batchSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSum, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
bool CryptoContextImpl<Element>::SerializeEvalAutomorphismKey(std::ostream& ser, Serializable::Type sertype, string id) {
	decltype(evalAutomorphismKeyMap)*	smap;
	decltype(evalAutomorphismKeyMap)		omap;
	if( id.length() == 0 )
		smap = &evalAutomorphismKeyMap;
	else {
		auto k = evalAutomorphismKeyMap.find(id);

		if( k == evalAutomorphismKeyMap.end() )
			return false; // no such id

		smap = &omap;
		omap[ k->first ] = k->second;
	}
	Serializable::Serialize(*smap, ser, sertype);
	return true;
}

template <typename Element>
bool CryptoContextImpl<Element>::SerializeEvalAutomorphismKey(std::ostream& ser, Serializable::Type sertype, const CryptoContext<Element> cc) {

	decltype(evalAutomorphismKeyMap) omap;
	for( const auto& k : evalAutomorphismKeyMap ) {
		if( k.second->begin()->second->GetCryptoContext() == cc ) {
			omap[k.first] = k.second;
		}
	}

	if( omap.size() == 0 )
		return false;

	Serializable::Serialize(omap, ser, sertype);
	return true;
}

template <typename Element>
bool CryptoContextImpl<Element>::DeserializeEvalAutomorphismKey(std::istream& ser, Serializable::Type sertype) {

	decltype(evalAutomorphismKeyMap) evalSumKeys;

	Serializable::Deserialize(evalSumKeys, ser, sertype);

	// The deserialize call created any contexts that needed to be created.... so all we need to do
	// is put the keys into the maps for their context

	for( auto k : evalSumKeys ) {
		evalAutomorphismKeyMap[ k.first ] = k.second;
	}

	return true;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const {

	if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
		throw std::logic_error("Information passed to EvalAtIndex was not generated with this crypto context");

	auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalAtIndex(ciphertext, index, evalAutomorphismKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalAtIndex, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalMerge(const vector<Ciphertext<Element>> &ciphertextVector) const {

	if( ciphertextVector[0] == NULL || Mismatched(ciphertextVector[0]->GetCryptoContext()) )
		throw std::logic_error("Information passed to EvalMerge was not generated with this crypto context");

	auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertextVector[0]->GetKeyTag());
	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalMerge(ciphertextVector, evalAutomorphismKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMerge, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2, usint batchSize) const {

	if( ct1 == NULL || ct2 == NULL || ct1->GetKeyTag() != ct2->GetKeyTag() ||
			Mismatched(ct1->GetCryptoContext()) )
		throw std::logic_error("Information passed to EvalInnerProduct was not generated with this crypto context");

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());
	auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys, ek[0]);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalInnerProduct, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1, ConstPlaintext ct2, usint batchSize) const {

	if( ct1 == NULL || ct2 == NULL || Mismatched(ct1->GetCryptoContext()) )
		throw std::logic_error("Information passed to EvalInnerProduct was not generated with this crypto context");

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalInnerProduct, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element>
CryptoContextImpl<Element>::EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
		usint indexStart, usint length) const {

	//need to add exception handling

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap((*x)(0,0).GetNumerator()->GetKeyTag());
	auto ek = GetEvalMultKeyVector((*x)(0,0).GetNumerator()->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalCrossCorrelation(x, y, batchSize, indexStart, length, evalSumKeys, ek[0]);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalCrossCorrelation, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Matrix<RationalCiphertext<Element>>>
CryptoContextImpl<Element>::EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize) const
		{
	//need to add exception handling

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap((*x)(0,0).GetNumerator()->GetKeyTag());
	auto ek = GetEvalMultKeyVector((*x)(0,0).GetNumerator()->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalLinRegressBatched(x, y, batchSize, evalSumKeys, ek[0]);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalLinRegressionBatched, currentDateTime() - start) );
	}
	return rv;
		}

// returns a shared pointer to a parameter object of the proper type; we deserialize into this object
template <typename Element>
static shared_ptr<LPCryptoParameters<Element>> GetParameterObject(string& parmstype) {

	if (parmstype == "LPCryptoParametersLTV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersLTV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBGV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersBGV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBFV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersBFV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBFVrns") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersBFVrns<Element>());
	}
	else if (parmstype == "LPCryptoParametersBFVrnsB") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersBFVrnsB<Element>());
	}
	else if (parmstype == "LPCryptoParametersStehleSteinfeld") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersStehleSteinfeld<Element>());
	}
	else if (parmstype == "LPCryptoParametersNull") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersNull<Element>());
	}

	return shared_ptr<LPCryptoParameters<Element>>();
}

// helper for deserialization of contexts
template <typename Element>
static shared_ptr<LPPublicKeyEncryptionScheme<Element>> GetSchemeObject(string& parmstype) {

	if (parmstype == "LPCryptoParametersLTV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeLTV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBGV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeBGV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBFV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeBFV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBFVrns") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeBFVrns<Element>());
	}
	else if (parmstype == "LPCryptoParametersBFVrnsB") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeBFVrnsB<Element>());
	}
	else if (parmstype == "LPCryptoParametersStehleSteinfeld") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>());
	}
	else if (parmstype == "LPCryptoParametersNull") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeNull<Element>());
	}

	return shared_ptr<LPPublicKeyEncryptionScheme<Element>>();
}

template <typename Element>
vector<CryptoContext<Element>>	CryptoContextFactory<Element>::AllContexts;

template <typename Element>
void
CryptoContextFactory<Element>::ReleaseAllContexts() {
	AllContexts.clear();
}

template <typename Element>
int
CryptoContextFactory<Element>::GetContextCount() {
	return AllContexts.size();
}

template <typename Element>
CryptoContext<Element>
CryptoContextFactory<Element>::GetSingleContext() {
	if( GetContextCount() == 1 )
		return AllContexts[0];
	throw std::logic_error("More than one context");
}

template <typename Element>
CryptoContext<Element>
CryptoContextFactory<Element>::GetContext(
		shared_ptr<LPCryptoParameters<Element>> params,
		shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme) {

	for( CryptoContext<Element> cc : AllContexts ) {
		if( *cc->GetEncryptionAlgorithm().get() == *scheme.get() &&
				*cc->GetCryptoParameters().get() == *params.get() ) {
			return cc;
		}
	}

	CryptoContext<Element> cc(new CryptoContextImpl<Element>(params,scheme));
	AllContexts.push_back(cc);
	return cc;
}

template <typename Element>
CryptoContext<Element>
CryptoContextFactory<Element>::GetContextForPointer(
		CryptoContextImpl<Element>* cc) {
	for( CryptoContext<Element> ctx : AllContexts ) {
		if( ctx.get() == cc )
			return ctx;
	}
	return 0;
}

//template <typename Element>
//CryptoContext<Element>
//CryptoContextFactory<Element>::DeserializeAndCreateContext(std::istream& ser, Serializable::Type serType) {
//
//	CryptoContext<Element> newcc;
//
//	//	try {
//	Serializable::Deserialize(newcc, ser, serType);
//	//	}
//	//	catch( exception& e ) {
//	//		return 0;
//	//	}
//
//	return CryptoContextFactory<Element>::GetContext(newcc->GetCryptoParameters(), newcc->GetEncryptionAlgorithm());
//}

template <typename T>
const vector<CryptoContext<T>>& CryptoContextFactory<T>::GetAllContexts() { return AllContexts; }

// factory methods for the different schemes

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, int depth, int assuranceMeasure, float securityLevel)
		{
	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>(
			ep,
			plaintextmodulus,
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(shared_ptr<typename T::Params> ep,
		EncodingParams encodingParams,
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

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(
		const PlaintextModulus plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
		{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in LTV context constructor");

	usint depth = numAdds + numMults + numKeyswitches + 1;

	shared_ptr<typename T::Params> ep( new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)) );

	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>(
			ep,
			EncodingParams(new EncodingParamsImpl(plaintextModulus)),
			dist,
			9.0,
			securityLevel,
			relinWindow,
			depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeLTV<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(
		EncodingParams encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in LTV context constructor");

	usint depth = numAdds + numMults + numKeyswitches + 1;

	shared_ptr<typename T::Params> ep(new typename T::Params(0, 0, 0));

	shared_ptr<LPCryptoParametersLTV<T>> params(
			new LPCryptoParametersLTV<T>(
					ep,
					encodingParams,
					dist,
					9.0,
					securityLevel,
					relinWindow,
					depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	if( scheme->ParamsGen(params, numAdds, numMults, numKeyswitches) == false )
		return 0;

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
		const std::string& bigmodulusarb, const std::string& bigrootofunityarb, int maxDepth)
		{
	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(ep,
					plaintextmodulus,
					stDev,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					typename T::Integer(delta),
					mode,
					typename T::Integer(bigmodulus),
					typename T::Integer(bigrootofunity),
					typename T::Integer(bigmodulusarb),
					typename T::Integer(bigrootofunityarb),
					depth,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBFV<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(shared_ptr<typename T::Params> ep,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
		const std::string& bigmodulusarb, const std::string& bigrootofunityarb, int maxDepth)
		{
	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(ep,
					encodingParams,
					stDev,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					typename T::Integer(delta),
					mode,
					typename T::Integer(bigmodulus),
					typename T::Integer(bigrootofunity),
					typename T::Integer(bigmodulusarb),
					typename T::Integer(bigrootofunityarb),
					depth,
					maxDepth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFV<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(
		const PlaintextModulus plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth)
		{

	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

	return genCryptoContextBFV(encodingParams,securityLevel,relinWindow, dist,
			numAdds, numMults, numKeyswitches, mode, maxDepth);

		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(
		EncodingParams encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFV context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					typename T::Integer(0),
					mode,
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(
		EncodingParams encodingParams, SecurityLevel securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFV context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					typename T::Integer(0),
					mode,
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		const PlaintextModulus plaintextModulus, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)) );

	shared_ptr<LPCryptoParametersBFVrns<T>> params( new LPCryptoParametersBFVrns<T>(
			ep,
			EncodingParams(new EncodingParamsImpl(plaintextModulus)),
			dist,
			36.0,
			securityLevel,
			relinWindow,
			mode,
			1,
			maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBFVrns<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		const PlaintextModulus plaintextModulus, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{

	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

	return genCryptoContextBFVrns(encodingParams, securityLevel, dist, numAdds, numMults,
			numKeyswitches, mode, maxDepth, relinWindow, dcrtBits);

		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		EncodingParams encodingParams, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrns<T>> params(
			new LPCryptoParametersBFVrns<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrns<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrns<T>> params(
			new LPCryptoParametersBFVrns<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrns<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		const PlaintextModulus plaintextModulus, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrnsB context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)) );

	shared_ptr<LPCryptoParametersBFVrnsB<T>> params( new LPCryptoParametersBFVrnsB<T>(
			ep,
			EncodingParams(new EncodingParamsImpl(plaintextModulus)),
			dist,
			36.0,
			securityLevel,
			relinWindow,
			mode,
			1,
			maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBFVrnsB<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		const PlaintextModulus plaintextModulus, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{

	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

	return genCryptoContextBFVrnsB(encodingParams, securityLevel, dist, numAdds, numMults,
			numKeyswitches, mode, maxDepth, relinWindow, dcrtBits);

		}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		EncodingParams encodingParams, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrnsB context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrnsB<T>> params(
			new LPCryptoParametersBFVrnsB<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrnsB<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrnsB context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrnsB<T>> params(
			new LPCryptoParametersBFVrnsB<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrnsB<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBGV(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode, int depth)
		{
	shared_ptr<LPCryptoParametersBGV<T>> params( new LPCryptoParametersBGV<T>(
			ep,
			plaintextmodulus,
			stDev,
			36, // assuranceMeasure,
			1.006, // securityLevel,
			relinWindow, // Relinearization Window
			mode, //Mode of noise generation
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBGV<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBGV(shared_ptr<typename T::Params> ep,
		EncodingParams encodingParams,
		usint relinWindow, float stDev,
		MODE mode, int depth)
		{
	shared_ptr<LPCryptoParametersBGV<T>> params(new LPCryptoParametersBGV<T>(
			ep,
			encodingParams,
			stDev,
			36, // assuranceMeasure,
			1.006, // securityLevel,
			relinWindow, // Relinearization Window
			mode, //Mode of noise generation
			depth
	));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBGV<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
		{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params( new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			plaintextmodulus,
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			stDevStSt,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		EncodingParams encodingParams,
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

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <>
CryptoContext<Poly>
CryptoContextFactory<Poly>::genCryptoContextNull(unsigned int m, const PlaintextModulus ptModulus)
{
	shared_ptr<typename Poly::Params> ep( new typename Poly::Params(m, typename Poly::Integer(ptModulus), 1) );
	shared_ptr<LPCryptoParametersNull<Poly>> params( new LPCryptoParametersNull<Poly>(ep, ptModulus) );
	shared_ptr<LPPublicKeyEncryptionScheme<Poly>> scheme( new LPPublicKeyEncryptionSchemeNull<Poly>() );

	return CryptoContextFactory<Poly>::GetContext(params,scheme);
}

template <>
CryptoContext<NativePoly>
CryptoContextFactory<NativePoly>::genCryptoContextNull(unsigned int m, const PlaintextModulus ptModulus)
{
	shared_ptr<typename NativePoly::Params> ep( new typename NativePoly::Params(m, typename NativePoly::Integer(ptModulus), 1) );
	shared_ptr<LPCryptoParametersNull<NativePoly>> params( new LPCryptoParametersNull<NativePoly>(ep, ptModulus) );
	shared_ptr<LPPublicKeyEncryptionScheme<NativePoly>> scheme( new LPPublicKeyEncryptionSchemeNull<NativePoly>() );

	return CryptoContextFactory<NativePoly>::GetContext(params,scheme);
}

template <>
CryptoContext<DCRTPoly>
CryptoContextFactory<DCRTPoly>::genCryptoContextNull(unsigned int m, const PlaintextModulus ptModulus)
{
	vector<NativeInteger> moduli = {ptModulus};
	vector<NativeInteger> roots = {1};
	shared_ptr<typename DCRTPoly::Params> ep( new typename DCRTPoly::Params(m, moduli, roots) );
	shared_ptr<LPCryptoParametersNull<DCRTPoly>> params( new LPCryptoParametersNull<DCRTPoly>(ep, ptModulus) );
	shared_ptr<LPPublicKeyEncryptionScheme<DCRTPoly>> scheme( new LPPublicKeyEncryptionSchemeNull<DCRTPoly>() );

	return CryptoContextFactory<DCRTPoly>::GetContext(params,scheme);
}

template <>
CryptoContext<DCRTPoly>
CryptoContextFactory<DCRTPoly>::genCryptoContextNull(unsigned int m, EncodingParams encodingParams)
{
	vector<NativeInteger> moduli = {encodingParams->GetPlaintextModulus()};
	vector<NativeInteger> roots = {1};
	shared_ptr<typename DCRTPoly::Params> ep( new typename DCRTPoly::Params(m, moduli, roots) );
	shared_ptr<LPCryptoParametersNull<DCRTPoly>> params( new LPCryptoParametersNull<DCRTPoly>(ep, encodingParams) );
	shared_ptr<LPPublicKeyEncryptionScheme<DCRTPoly>> scheme( new LPPublicKeyEncryptionSchemeNull<DCRTPoly>() );

	return CryptoContextFactory<DCRTPoly>::GetContext(params,scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextNull(unsigned int m, EncodingParams encodingParams)
{
	shared_ptr<typename T::Params> ep( new typename T::Params(m, encodingParams->GetPlaintextModulus(), 1) );
	shared_ptr<LPCryptoParametersNull<T>> params( new LPCryptoParametersNull<T>(ep, encodingParams) );
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeNull<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

}

