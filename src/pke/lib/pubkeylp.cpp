/*
 * pubkeylp.cpp
 *
 *  Created on: May 21, 2017
 *      Author: gerardryan
 */

#include "pubkeylp.h"

namespace lbcrypto {

template<typename Element>
bool LPPublicKey<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "PublicKey", serObj->GetAllocator());

	if (!this->GetCryptoParameters()->Serialize(serObj)) {
		return false;
	}

	SerializeVector<Element>("Vectors", this->GetPublicElements()[0]->GetElementName(), this->GetPublicElements(), serObj);

	return true;
}

template<typename Element>
bool LPPublicKey<Element>::Deserialize(const Serialized &serObj) {

	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "PublicKey" )
		return false;

	mIt = serObj.FindMember("Vectors");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	bool ret = DeserializeVector<Element>("Vectors", Element::ElementName, mIt, &this->m_h);

	return ret;
}

template<typename Element>
bool LPEvalKeyRelin<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "EvalKeyRelin", serObj->GetAllocator());

	if (!this->GetCryptoParameters()->Serialize(serObj)) {
		return false;
	}

	SerializeVector<Element>("AVector", Element::ElementName, this->m_rKey[0], serObj);
	SerializeVector<Element>("BVector", Element::ElementName, this->m_rKey[1], serObj);

	return true;
}

template<typename Element>
bool LPEvalKeyRelin<Element>::Deserialize(const Serialized &serObj) {

	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyRelin" )
		return false;

	mIt = serObj.FindMember("AVector");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	std::vector<Element> deserElem;
	bool ret = DeserializeVector<Element>("AVector", Element::ElementName, mIt, &deserElem);
	this->m_rKey.push_back(deserElem);

	if( !ret ) return ret;

	mIt = serObj.FindMember("BVector");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	ret = DeserializeVector<Element>("BVector", Element::ElementName, mIt, &deserElem);
	this->m_rKey.push_back(deserElem);

	return ret;
}

template<typename Element>
bool LPEvalKeyNTRURelin<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "EvalKeyNTRURelin", serObj->GetAllocator());

	if (!this->GetCryptoParameters()->Serialize(serObj)) {
		return false;
	}

	SerializeVector<Element>("Vectors", Element::ElementName, this->GetAVector(), serObj);

	return true;
}

template<typename Element>
bool LPEvalKeyNTRURelin<Element>::Deserialize(const Serialized &serObj) {
	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyNTRURelin" )
		return false;

	SerialItem::ConstMemberIterator it = serObj.FindMember("Vectors");

	if( it == serObj.MemberEnd() ) {
		return false;
	}

	std::vector<Element> newElements;
	if( DeserializeVector<Element>("Vectors", Element::ElementName, it, &newElements) ) {
		this->SetAVector(newElements);
		return true;
	}

	return false;
}


}
