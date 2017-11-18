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
std::map<string,std::vector<shared_ptr<LPEvalKey<Element>>>>	CryptoContext<Element>::evalMultKeyMap;

template <typename Element>
std::map<string,shared_ptr<std::map<usint,shared_ptr<LPEvalKey<Element>>>>>	CryptoContext<Element>::evalSumKeyMap;

template <typename Element>
void CryptoContext<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> key) {

	if( key == NULL || Mismatched(key->GetCryptoContext()) )
		throw std::logic_error("Key passed to EvalMultKeyGen were not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();

	shared_ptr<LPEvalKey<Element>> k = GetEncryptionAlgorithm()->EvalMultKeyGen(key);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMultKeyGen, currentDateTime() - start) );
	}

	evalMultKeyMap[ k->GetKeyTag() ] = { k };
}

template <typename Element>
const vector<shared_ptr<LPEvalKey<Element>>>& CryptoContext<Element>::GetEvalMultKeyVector(const string& keyID) {
	auto ekv = evalMultKeyMap.find(keyID);
	if( ekv == evalMultKeyMap.end() )
		throw std::logic_error("You need to use EvalMultKeyGen so that you have an EvalMultKey available for this ID");
	return ekv->second;
}

template <typename Element>
const std::map<string,std::vector<shared_ptr<LPEvalKey<Element>>>>& CryptoContext<Element>::GetAllEvalMultKeys() {
	return evalMultKeyMap;
}

template <typename Element>
void CryptoContext<Element>::ClearEvalMultKeys() {
	evalMultKeyMap.clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContext<Element>::ClearEvalMultKeys(const string& id) {
	auto kd = evalMultKeyMap.find(id);
	if( kd != evalMultKeyMap.end() )
		evalMultKeyMap.erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContext<Element>::ClearEvalMultKeys(const shared_ptr<CryptoContext> cc) {
	for( auto it = evalMultKeyMap.begin(); it != evalMultKeyMap.end(); ) {
		if( it->second[0]->GetCryptoContext() == cc ) {
			it = evalMultKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContext<Element>::InsertEvalMultKey(const std::vector<shared_ptr<LPEvalKey<Element>>>& vectorToInsert) {
	evalMultKeyMap[ vectorToInsert[0]->GetKeyTag() ] = vectorToInsert;
}

template <typename Element>
void CryptoContext<Element>::EvalSumKeyGen(
	const shared_ptr<LPPrivateKey<Element>> privateKey,
	const shared_ptr<LPPublicKey<Element>> publicKey) {

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
const std::map<usint, shared_ptr<LPEvalKey<Element>>>& CryptoContext<Element>::GetEvalSumKeyMap(const string& keyID) {
	auto ekv = evalSumKeyMap.find(keyID);
	if( ekv == evalSumKeyMap.end() )
		throw std::logic_error("You need to use EvalSumKeyGen so that you have EvalSumKeys available for this ID");
	return *ekv->second;
}

template <typename Element>
const std::map<string,shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>>>& CryptoContext<Element>::GetAllEvalSumKeys() {
	return evalSumKeyMap;
}

template <typename Element>
void CryptoContext<Element>::ClearEvalSumKeys() {
	evalSumKeyMap.clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContext<Element>::ClearEvalSumKeys(const string& id) {
	auto kd = evalSumKeyMap.find(id);
	if( kd != evalSumKeyMap.end() )
		evalSumKeyMap.erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContext<Element>::ClearEvalSumKeys(const shared_ptr<CryptoContext> cc) {
	for( auto it = evalSumKeyMap.begin(); it != evalSumKeyMap.end(); ) {
		if( it->second->begin()->second->GetCryptoContext() == cc ) {
			it = evalSumKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContext<Element>::InsertEvalSumKey(const shared_ptr<std::map<usint,shared_ptr<LPEvalKey<Element>>>> mapToInsert) {
	// find the tag
	auto onekey = mapToInsert->begin();
	evalSumKeyMap[ onekey->second->GetKeyTag() ] = mapToInsert;
}

/**
 * SerializeEvalMultKey for all EvalMult keys
 * method will serialize each CryptoContext only once
 */
template <typename Element>
bool CryptoContext<Element>::SerializeEvalMultKey(Serialized* serObj) {
	serObj->SetObject();
	serObj->AddMember("Object", "EvalMultKeys", serObj->GetAllocator());
	serObj->AddMember("Count", std::to_string(CryptoContextFactory<Element>::GetContextCount()), serObj->GetAllocator());

	int sCount = 0;

	for( auto& cc : CryptoContextFactory<Element>::GetAllContexts() ) {
		Serialized cSer(rapidjson::kObjectType, &serObj->GetAllocator());
		if( CryptoContext<Element>::SerializeEvalMultKey(&cSer, cc) ) {
			serObj->AddMember(SerialItem(std::to_string(sCount), serObj->GetAllocator()), cSer.Move(), serObj->GetAllocator());
		}
		++sCount;
	}
	return true;
}

/**
 * SerializeEvalMultKey for a single EvalMult key
 * method will serialize entire key AND cryptocontext
 */
template <typename Element>
bool CryptoContext<Element>::SerializeEvalMultKey(Serialized* serObj, const string& id) {
	auto k = evalMultKeyMap.find(id);

	if( k == evalMultKeyMap.end() )
		return false; // no such id

	serObj->SetObject();
	k->second[0]->GetCryptoContext()->Serialize(serObj);
	serObj->AddMember("Object", "EvalMultKey", serObj->GetAllocator());
	SerializeVectorOfPointers<LPEvalKey<Element>>("EvalMultKeys", "LPEvalKey", k->second, serObj);
	return true;
}

/**
 * SerializeEvalMultKey for all EvalMultKeys made in a given context
 * method will serialize the context only once
 */
template <typename Element>
bool CryptoContext<Element>::SerializeEvalMultKey(Serialized* serObj, const shared_ptr<CryptoContext> cc) {

	serObj->SetObject();
	cc->Serialize(serObj);
	serObj->AddMember("Object", "EvalMultKeyOneContext", serObj->GetAllocator());
	for( const auto& k : evalMultKeyMap ) {
		if( k.second[0]->GetCryptoContext() == cc ) {
			SerializeVectorOfPointers<LPEvalKey<Element>>("EvalMultKeys", "LPEvalKey", k.second, serObj);
		}
	}
	return true;
}

template <typename Element>
bool CryptoContext<Element>::DeserializeEvalMultKey(const Serialized& ser) {
	Serialized serObj;
	serObj.CopyFrom(ser, serObj.GetAllocator()); // copy, because we will destroy it

	Serialized::MemberIterator cIter = serObj.FindMember("Object");
	if( cIter == serObj.MemberEnd() )
		return false;

	// something different for EvalMultKey, EvalMultKeyOneContext, and EvalMultKeys

	// figure out how many key sets there are
	int cCount = 1;
	bool singleton = true;
	if( cIter->value.GetString() == string("EvalMultKeys") ) {
		Serialized::ConstMemberIterator cntIter = serObj.FindMember("Count");
		if( cntIter == serObj.MemberEnd() )
			return false;

		cCount = std::stoi(cntIter->value.GetString());
		singleton = false;
	}

	if( singleton &&
			cIter->value.GetString() != string("EvalMultKey") &&
					cIter->value.GetString() != string("EvalMultKeyOneContext") ) {
		throw std::logic_error("DeserializeEvalMultKey passed an unknown object type " + string(cIter->value.GetString()));
	}

	for( int keysets = 0; keysets < cCount; keysets++ ) {

		// get the crypto context for this keyset
		shared_ptr<CryptoContext<Element>> cc;
		Serialized *serPtr;
		Serialized oneSer;
		if( singleton ) {
			cc = CryptoContextFactory<Element>::DeserializeAndCreateContext(serObj);
			serPtr = &serObj;
		}
		else {
			Serialized::MemberIterator ksIter = serObj.FindMember(std::to_string(keysets));
			if( ksIter == serObj.MemberEnd() )
				return false;

			oneSer.SetObject();
			for( Serialized::MemberIterator i = ksIter->value.MemberBegin(); i != ksIter->value.MemberEnd(); i++ ) {
				oneSer.AddMember( SerialItem(i->name,serObj.GetAllocator()),
						SerialItem(i->value,serObj.GetAllocator()),
						serObj.GetAllocator() );
			}

			serPtr = &oneSer;
			cc = CryptoContextFactory<Element>::DeserializeAndCreateContext(oneSer);
		}

		Serialized::MemberIterator kIter;

		// now, find and deserialize all keys
		for( kIter = serPtr->MemberBegin(); kIter != serPtr->MemberEnd(); ) {
			if( kIter->name.GetString() != string("EvalMultKeys") ) {
				kIter = serPtr->RemoveMember(kIter);
				continue;
			}

			// sadly we cannot DeserializeVectorOfPointers because of polymorphism in the pointer type...
			vector<shared_ptr<LPEvalKey<Element>>> evalMultKeys;
			evalMultKeys.clear();

			Serialized kser;
			kser.SetObject();
			kser.AddMember(SerialItem(kIter->name, kser.GetAllocator()), SerialItem(kIter->value, kser.GetAllocator()), kser.GetAllocator());

			Serialized ktemp;
			ktemp.SetObject();
			auto keyValue = SerialItem(kIter->value, ktemp.GetAllocator());

			Serialized::ConstMemberIterator t = keyValue.FindMember("Length");
			if( t == keyValue.MemberEnd() )
				throw std::logic_error("Unable to find number of eval mult keys in serialization");
			usint nKeys = std::stoi(t->value.GetString());

			t = keyValue.FindMember("Typename");
			if( t == keyValue.MemberEnd() )
				throw std::logic_error("Unable to find eval mult key type in serialization");
			string ty = t->value.GetString();

			t = keyValue.FindMember("Members");
			if( t == keyValue.MemberEnd() )
				throw std::logic_error("Unable to find eval mult keys in serialization");
			const SerialItem& members = t->value;

			for( size_t k = 0; k < nKeys; k++ ) {
				shared_ptr<LPEvalKey<Element>> kp;

				Serialized::ConstMemberIterator eIt = members.FindMember( std::to_string(k) );
				if( eIt == members.MemberEnd() )
					throw std::logic_error("Unable to find eval mult key #" + std::to_string(k) + " in serialization");

				auto keyMember = SerialItem(eIt->value, ktemp.GetAllocator());
				Serialized kser(rapidjson::kObjectType);

				Serialized::ConstMemberIterator t = keyMember.MemberBegin();
				while( t != keyMember.MemberEnd() ) {
					kser.AddMember(SerialItem(t->name, kser.GetAllocator()), SerialItem(t->value, kser.GetAllocator()), kser.GetAllocator());
					t++;
				}

				kp = CryptoContext<Element>::deserializeEvalKeyInContext(kser,cc);
				evalMultKeys.push_back(kp);
			}

			kIter = serPtr->EraseMember(kIter);

			evalMultKeyMap[evalMultKeys[0]->GetKeyTag()] = evalMultKeys;
		}
	}

	return true;
}

/**
 * SerializeEvalSumKey for all EvalSum keys
 * method will serialize each CryptoContext only once
 */
template <typename Element>
bool CryptoContext<Element>::SerializeEvalSumKey(Serialized* serObj) {
	serObj->SetObject();
	serObj->AddMember("Object", "EvalSumKeys", serObj->GetAllocator());
	serObj->AddMember("Count", std::to_string(CryptoContextFactory<Element>::GetContextCount()), serObj->GetAllocator());

	int sCount = 0;

	for( auto& cc : CryptoContextFactory<Element>::GetAllContexts() ) {
		Serialized cSer(rapidjson::kObjectType, &serObj->GetAllocator());
		if( CryptoContext<Element>::SerializeEvalSumKey(&cSer, cc) ) {
			serObj->AddMember(SerialItem(std::to_string(sCount), serObj->GetAllocator()), cSer.Move(), serObj->GetAllocator());
		}
		++sCount;
	}
	return true;
}

/**
 * SerializeEvalSumKey for a single EvalSum key
 * method will serialize entire key AND cryptocontext
 */
template <typename Element>
bool CryptoContext<Element>::SerializeEvalSumKey(Serialized* serObj, const string& id) {
	auto k = evalSumKeyMap.find(id);

	if( k == evalSumKeyMap.end() )
		return false; // no such id

	serObj->SetObject();
	k->second->begin()->second->GetCryptoContext()->Serialize(serObj);
	serObj->AddMember("Object", "EvalSumKey", serObj->GetAllocator());
	SerializeMapOfPointers("EvalSumKeys", "LPEvalKey", *k->second, serObj);
	return true;
}

/**
 * SerializeEvalSumKey for all EvalSumKeys made in a given context
 * method will serialize the context only once
 */
template <typename Element>
bool CryptoContext<Element>::SerializeEvalSumKey(Serialized* serObj, const shared_ptr<CryptoContext> cc) {

	serObj->SetObject();
	cc->Serialize(serObj);
	serObj->AddMember("Object", "EvalSumKeyOneContext", serObj->GetAllocator());
	for( const auto& k : evalSumKeyMap ) {
		if( k.second->begin()->second->GetCryptoContext() == cc ) {
			SerializeMapOfPointers("EvalSumKeys", "LPEvalKey", *k.second, serObj);
		}
	}
	return true;
}

template <typename Element>
bool CryptoContext<Element>::DeserializeEvalSumKey(const Serialized& ser) {
	Serialized serObj;
	serObj.CopyFrom(ser, serObj.GetAllocator()); // copy, because we will destroy it

	Serialized::MemberIterator cIter = serObj.FindMember("Object");
	if( cIter == serObj.MemberEnd() )
		return false;

	// something different for EvalSumKey, EvalSumKeyOneContext, and EvalSumKeys

	// figure out how many key sets there are
	int cCount = 1;
	bool singleton = true;
	if( cIter->value.GetString() == string("EvalSumKeys") ) {
		Serialized::ConstMemberIterator cntIter = serObj.FindMember("Count");
		if( cntIter == serObj.MemberEnd() )
			return false;

		cCount = std::stoi(cntIter->value.GetString());
		singleton = false;
	}

	if( singleton &&
			cIter->value.GetString() != string("EvalSumKey") &&
					cIter->value.GetString() != string("EvalSumKeyOneContext") ) {
		throw std::logic_error("DeserializeEvalMultKey passed an unknown object type " + string(cIter->value.GetString()));
	}

	for( int keysets = 0; keysets < cCount; keysets++ ) {

		// get the crypto context for this keyset
		shared_ptr<CryptoContext<Element>> cc;
		Serialized *serPtr;
		Serialized oneSer;
		if( singleton ) {
			cc = CryptoContextFactory<Element>::DeserializeAndCreateContext(serObj);
			serPtr = &serObj;
		}
		else {
			Serialized::MemberIterator ksIter = serObj.FindMember(std::to_string(keysets));
			if( ksIter == serObj.MemberEnd() )
				return false;

			oneSer.SetObject();
			for( Serialized::MemberIterator i = ksIter->value.MemberBegin(); i != ksIter->value.MemberEnd(); i++ ) {
				oneSer.AddMember( SerialItem(i->name,serObj.GetAllocator()),
						SerialItem(i->value,serObj.GetAllocator()),
						serObj.GetAllocator() );
			}

			serPtr = &oneSer;
			cc = CryptoContextFactory<Element>::DeserializeAndCreateContext(oneSer);
		}

		Serialized::MemberIterator kIter;

		// now, find and deserialize all keys
		for( kIter = serPtr->MemberBegin(); kIter != serPtr->MemberEnd(); ) {
			if( kIter->name.GetString() != string("EvalSumKeys") ) {
				kIter = serPtr->RemoveMember(kIter);
				continue;
			}

			shared_ptr<map<usint,shared_ptr<LPEvalKey<Element>>>> evalSumKeys( new map<usint,shared_ptr<LPEvalKey<Element>>>() );
			string keyTag = "";

			Serialized kser;
			kser.SetObject();
			kser.AddMember(SerialItem(kIter->name, kser.GetAllocator()), SerialItem(kIter->value, kser.GetAllocator()), kser.GetAllocator());

			Serialized ktemp;
			ktemp.SetObject();
			auto keyValue = SerialItem(kIter->value, ktemp.GetAllocator());

			Serialized::ConstMemberIterator t = keyValue.FindMember("Members");
			if( t == keyValue.MemberEnd() )
				throw std::logic_error("Unable to find eval sum keys in serialization");
			const SerialItem& members = t->value;

            for( Serialized::ConstMemberIterator mI = members.MemberBegin(); mI != members.MemberEnd(); mI++ ) {

				shared_ptr<LPEvalKey<Element>> kp;

                usint k = std::stoi( mI->name.GetString() );

                Serialized kser(rapidjson::kObjectType);
                auto keyMember = SerialItem(mI->value, kser.GetAllocator());

                Serialized::ConstMemberIterator t = keyMember.MemberBegin();
				while( t != keyMember.MemberEnd() ) {
                    kser.AddMember(SerialItem(t->name, kser.GetAllocator()), SerialItem(t->value, kser.GetAllocator()), kser.GetAllocator());
                    t++;
				}

				kp = cc->deserializeEvalKeyInContext(kser,cc);

				if( keyTag == "" )
					keyTag = kp->GetKeyTag();

				(*evalSumKeys)[k] = kp;
			}

			kIter = serPtr->EraseMember(kIter);

			evalSumKeyMap[keyTag] = evalSumKeys;
		}
	}

	return true;
}


template <typename Element>
shared_ptr<Ciphertext<Element>> CryptoContext<Element>::EvalSum(const shared_ptr<Ciphertext<Element>> ciphertext, usint batchSize) const {

	if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
		throw std::logic_error("Information passed to EvalAdd was not generated with this crypto context");

	auto evalSumKeys = CryptoContext<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());
	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalSum(ciphertext, batchSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSum, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Ciphertext<Element>> CryptoContext<Element>::EvalInnerProduct(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2, usint batchSize) const {

	if( ct1 == NULL || ct2 == NULL || ct1->GetKeyTag() != ct2->GetKeyTag() ||
			Mismatched(ct1->GetCryptoContext()) )
		throw std::logic_error("Information passed to EvalInnerProduct was not generated with this crypto context");

	auto evalSumKeys = CryptoContext<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());
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
shared_ptr<Ciphertext<Element>>
CryptoContext<Element>::EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
		usint indexStart, usint length) const {

	//need to add exception handling

	auto evalSumKeys = CryptoContext<Element>::GetEvalSumKeyMap((*x)(0,0).GetNumerator()->GetKeyTag());
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
CryptoContext<Element>::EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize) const
{
	//need to add exception handling

	auto evalSumKeys = CryptoContext<Element>::GetEvalSumKeyMap((*x)(0,0).GetNumerator()->GetKeyTag());
	auto ek = GetEvalMultKeyVector((*x)(0,0).GetNumerator()->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalLinRegressBatched(x, y, batchSize, evalSumKeys, ek[0]);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalLinRegressionBatched, currentDateTime() - start) );
	}
	return rv;
}

template <typename T>
bool
CryptoContext<T>::Serialize(Serialized* serObj) const
{
	if( ! serObj->IsObject() )
		serObj->SetObject();

	Serialized ccser(rapidjson::kObjectType, &serObj->GetAllocator());

	Serialized pser(rapidjson::kObjectType, &serObj->GetAllocator());
	if( !params->Serialize(&pser) )
		return false;

	ccser.AddMember("Params", pser.Move(), serObj->GetAllocator());
	ccser.AddMember("Schemes", std::to_string(this->scheme->GetEnabled()), serObj->GetAllocator());

	serObj->AddMember("CryptoContext", ccser.Move(), serObj->GetAllocator());

	return true;
}

template <typename Element>
bool CryptoObject<Element>::SerializeCryptoObject(Serialized* serObj, bool includeContext) const
{
	serObj->SetObject();

	if( includeContext ) {
		if( this->context->Serialize(serObj) == false )
			return false;
	}

	serObj->AddMember("KeyTag", this->keyTag, serObj->GetAllocator());
	return true;
}

template <typename Element>
bool CryptoObject<Element>::DeserializeCryptoObject(const Serialized& serObj, bool includeContext) {

	if( includeContext ) {
		shared_ptr<CryptoContext<Element>> cc = CryptoContextFactory<Element>::DeserializeAndCreateContext(serObj);
		if( cc == 0 )
			return false;
	}

	Serialized::ConstMemberIterator pIter = serObj.FindMember("KeyTag");
	if( pIter == serObj.MemberEnd() )
		return false;

	this->SetKeyTag( pIter->value.GetString() );

	return true;
}

// returns a shared pointer to a parameter object of the proper type; we deserialize into this object
template <typename Element>
static shared_ptr<LPCryptoParameters<Element>> GetParameterObject(string& parmstype) {

	if (parmstype == "LPCryptoParametersLTV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersLTV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersBV<Element>());
	}
	else if (parmstype == "LPCryptoParametersFV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersFV<Element>());
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
	else if (parmstype == "LPCryptoParametersBV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeBV<Element>());
	}
	else if (parmstype == "LPCryptoParametersFV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeFV<Element>());
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
vector<shared_ptr<CryptoContext<Element>>>	CryptoContextFactory<Element>::AllContexts;

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
shared_ptr<CryptoContext<Element>>
CryptoContextFactory<Element>::GetSingleContext() {
	if( GetContextCount() == 1 )
		return AllContexts[0];
	throw std::logic_error("More than one context");
}

template <typename Element>
shared_ptr<CryptoContext<Element>>
CryptoContextFactory<Element>::GetContext(
		shared_ptr<LPCryptoParameters<Element>> params,
		shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme) {

	for( shared_ptr<CryptoContext<Element>> cc : AllContexts ) {
		if( *cc->GetEncryptionAlgorithm().get() == *scheme.get() &&
				*cc->GetCryptoParameters().get() == *params.get()
		) {
			return cc;
		}
	}

	shared_ptr<CryptoContext<Element>> cc(new CryptoContext<Element>(params,scheme));
	AllContexts.push_back(cc);
	return cc;
}

template <typename Element>
shared_ptr<CryptoContext<Element>>
CryptoContextFactory<Element>::GetContextForPointer(
		CryptoContext<Element>* cc) {
	for( shared_ptr<CryptoContext<Element>> ctx : AllContexts ) {
		if( ctx.get() == cc )
			return ctx;
	}
	return 0;
}

/**
* Create a PALISADE CryptoContext from a serialization
* @param serObj - the serialization
* @param noKeys - if true, do not deserialize the keys
* @return new context
*/
template <typename Element>
shared_ptr<CryptoContext<Element>>
CryptoContextFactory<Element>::DeserializeAndCreateContext(const Serialized& serObj) {

	Serialized::ConstMemberIterator mIter = serObj.FindMember("CryptoContext");
	if( mIter == serObj.MemberEnd() )
		throw std::logic_error("Serialization is not of a CryptoContext");

	// mIter->value has params and keys

	Serialized::ConstMemberIterator pIter = mIter->value.FindMember("Params");
	if( pIter == mIter->value.MemberEnd() )
		throw std::logic_error("Serialization is missing Params");

	// get parms type
	Serialized temp(rapidjson::kObjectType);
	auto parmValue = SerialItem(pIter->value, temp.GetAllocator());

	string parmName;
	pIter = parmValue.FindMember("LPCryptoParametersType");
	if (pIter == parmValue.MemberEnd()) {
		throw std::logic_error("Parameter serialization is missing Parameter type");
	}

	parmName = pIter->value.GetString();

	pIter = parmValue.FindMember(parmName);
	if (pIter == parmValue.MemberEnd()) {
		throw std::logic_error("Parameter serialization is missing Parameter value");
	}

	Serialized parm(rapidjson::kObjectType);
	parm.AddMember(SerialItem(pIter->name, parm.GetAllocator()), SerialItem(pIter->value, parm.GetAllocator()), parm.GetAllocator());

	shared_ptr<LPCryptoParameters<Element>> cp = GetParameterObject<Element>(parmName);

	if (cp == NULL) {
		throw std::logic_error("Unable to create crypto parameters");
	}

	if (!cp->Deserialize(parm)) {
		throw std::logic_error("Unable to deserialize crypto parameters for " + parmName);
	}

	shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme = GetSchemeObject<Element>(parmName);

	shared_ptr<CryptoContext<Element>> cc =
			CryptoContextFactory<Element>::GetContext(cp, scheme);

	Serialized::ConstMemberIterator sIter = mIter->value.FindMember("Schemes");
	if( sIter != mIter->value.MemberEnd() ) {
		usint schemeBits = std::stoi(sIter->value.GetString());
		cc->Enable(schemeBits);
	}

	return cc;
}

// factory methods for the different schemes

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextLTV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>(
			ep,
			BigInteger(plaintextmodulus),
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
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

	return CryptoContextFactory<T>::GetContext(params,scheme);
}


template <typename T>
shared_ptr<CryptoContext<T>>
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

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigInteger(0), BigInteger(0)) );

	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>(
			ep,
			shared_ptr<EncodingParams>( new EncodingParams(plaintextModulus) ),
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
shared_ptr<CryptoContext<T>>
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
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
		const std::string& bigmodulusarb, const std::string& bigrootofunityarb, int maxDepth)
{
	shared_ptr<LPCryptoParametersFV<T>> params(
			new LPCryptoParametersFV<T>(ep,
					BigInteger(plaintextmodulus),
					stDev,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					BigInteger(delta),
					mode,
					BigInteger(bigmodulus),
					BigInteger(bigrootofunity),
					BigInteger(bigmodulusarb),
					BigInteger(bigrootofunityarb),
					depth,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev, const std::string& delta,
	MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
	const std::string& bigmodulusarb, const std::string& bigrootofunityarb, int maxDepth)
{
	shared_ptr<LPCryptoParametersFV<T>> params(
		new LPCryptoParametersFV<T>(ep,
			encodingParams,
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			BigInteger(delta),
			mode,
			BigInteger(bigmodulus),
			BigInteger(bigrootofunity),
			BigInteger(bigmodulusarb),
			BigInteger(bigrootofunityarb),
			depth,
			maxDepth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeFV<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth)
{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in FV context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigInteger(0), BigInteger(0)) );

	shared_ptr<LPCryptoParametersFV<T>> params( new LPCryptoParametersFV<T>(
			ep,
			shared_ptr<EncodingParams>(new EncodingParams(plaintextModulus)),
			dist,
			9.0,
			securityLevel,
			relinWindow,
			BigInteger(0),
			mode,
			BigInteger(0),
			BigInteger(0),
			BigInteger(0),
			BigInteger(0),
			1,
			maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(
	shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
	unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth)
{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in FV context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, BigInteger(0), BigInteger(0)));

	shared_ptr<LPCryptoParametersFV<T>> params(
			new LPCryptoParametersFV<T>(
				ep,
				encodingParams,
				dist,
				9.0,
				securityLevel,
				relinWindow,
				BigInteger(0),
				mode,
				BigInteger(0),
				BigInteger(0),
				BigInteger(0),
				BigInteger(0),
				1,
				maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeFV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth)
{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigInteger(0), BigInteger(0)) );

	shared_ptr<LPCryptoParametersBFVrns<T>> params( new LPCryptoParametersBFVrns<T>(
			ep,
			shared_ptr<EncodingParams>(new EncodingParams(plaintextModulus)),
			dist,
			9.0,
			securityLevel,
			relinWindow,
			mode,
			1,
			maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBFVrns<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextBFVrns(
	shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
	unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth)
{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, BigInteger(0), BigInteger(0)));

	shared_ptr<LPCryptoParametersBFVrns<T>> params(
			new LPCryptoParametersBFVrns<T>(
				ep,
				encodingParams,
				dist,
				9.0,
				securityLevel,
				relinWindow,
				mode,
				1,
				maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrns<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContextFactory<T>::GetContext(params,scheme);
}


template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextBV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode, int depth)
{
	shared_ptr<LPCryptoParametersBV<T>> params( new LPCryptoParametersBV<T>(
		ep,
		BigInteger(plaintextmodulus),
		stDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode, //Mode of noise generation
		depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBV<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
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

	return CryptoContextFactory<T>::GetContext(params,scheme);
}


template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params( new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			BigInteger(plaintextmodulus),
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
shared_ptr<CryptoContext<T>>
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

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextNull(shared_ptr<typename T::Params> ep,
		const usint ptModulus)
{
	shared_ptr<LPCryptoParametersNull<T>> params( new LPCryptoParametersNull<T>(ep, BigInteger(ptModulus)) );
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeNull<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextNull(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams)
{
	shared_ptr<LPCryptoParametersNull<T>> params(new LPCryptoParametersNull<T>(ep, encodingParams));
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeNull<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

// the methods below allow me to deserialize a json object into this context
// ... which will only succeed if the object was serialized from this context,
// ... or from another context with identical parameters

template <typename T>
shared_ptr<LPPublicKey<T>>
CryptoContext<T>::deserializePublicKey(const Serialized& serObj)
{
	shared_ptr<CryptoContext<T>> cc = CryptoContextFactory<T>::DeserializeAndCreateContext(serObj);
	if( cc == 0 )
		return 0;

	shared_ptr<LPPublicKey<T>> key( new LPPublicKey<T>(cc) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPPublicKey<T>>();
}

template <typename T>
shared_ptr<LPPrivateKey<T>>
CryptoContext<T>::deserializeSecretKey(const Serialized& serObj)
{
	shared_ptr<CryptoContext<T>> cc = CryptoContextFactory<T>::DeserializeAndCreateContext(serObj);
	if( cc == 0 )
		return 0;

	shared_ptr<LPPrivateKey<T>> key( new LPPrivateKey<T>(cc) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPPrivateKey<T>>();
}

template <typename T>
shared_ptr<Ciphertext<T>>
CryptoContext<T>::deserializeCiphertext(const Serialized& serObj)
{
	shared_ptr<CryptoContext<T>> cc = CryptoContextFactory<T>::DeserializeAndCreateContext(serObj);
	if( cc == 0 )
		return 0;

	shared_ptr<Ciphertext<T>> ctxt( new Ciphertext<T>( cc ) );

	if( ctxt->Deserialize(serObj) )
		return ctxt;

	return shared_ptr<Ciphertext<T>>();
}

template <typename T>
shared_ptr<LPEvalKey<T>>
CryptoContext<T>::deserializeEvalKey(const Serialized& serObj)
{
	shared_ptr<CryptoContext<T>> cc = CryptoContextFactory<T>::DeserializeAndCreateContext(serObj);
	if( cc == 0 )
		return 0;

	return CryptoContext<T>::deserializeEvalKeyInContext(serObj, cc);
}

template <typename T>
shared_ptr<LPEvalKey<T>>
CryptoContext<T>::deserializeEvalKeyInContext(const Serialized& serObj, shared_ptr<CryptoContext<T>> cc)
{
	Serialized::ConstMemberIterator nIt = serObj.FindMember("Object");
	if( nIt == serObj.MemberEnd() )
		return 0;

	shared_ptr<LPEvalKey<T>> key;
	string oname = nIt->value.GetString();
	if( oname == "EvalKeyRelin" ) {
		LPEvalKeyRelin<T> *k = new LPEvalKeyRelin<T>(cc);
		if( k->Deserialize(serObj) == false )
			return 0;

		key.reset( k );
	}

	else if( oname == "EvalKeyNTRURelin" ) {
		LPEvalKeyNTRURelin<T> *k = new LPEvalKeyNTRURelin<T>(cc);
		if( k->Deserialize(serObj) == false )
			return 0;

		key.reset( k );
	}
	else if( oname == "EvalKeyNTRU" ) {
		LPEvalKeyNTRU<T> *k = new LPEvalKeyNTRU<T>(cc);
		if( k->Deserialize(serObj) == false )
			return 0;

		key.reset( k );
	}
	else
		throw std::logic_error("Unrecognized Eval Key type '" + oname + "'");

	return key;
}

}

