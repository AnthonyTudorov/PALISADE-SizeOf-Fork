/*
 * @file pubkeylp.cpp - public key implementation
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */
 
#include "cryptocontext.h"
#include "pubkeylp.h"

namespace lbcrypto {

template<typename Element>
bool LPPublicKey<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "PublicKey", serObj->GetAllocator());

	if (!this->GetCryptoParameters()->Serialize(serObj)) {
		return false;
	}

	SerializeVector<Element>("Vectors", Element::GetElementName(), this->GetPublicElements(), serObj);

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

	bool ret = DeserializeVector<Element>("Vectors", Element::GetElementName(), mIt, &this->m_h);

	return ret;
}

template<typename Element>
bool LPEvalKeyRelin<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "EvalKeyRelin", serObj->GetAllocator());

	if (!this->GetCryptoParameters()->Serialize(serObj)) {
		return false;
	}

	SerializeVector<Element>("AVector", Element::GetElementName(), this->m_rKey[0], serObj);
	SerializeVector<Element>("BVector", Element::GetElementName(), this->m_rKey[1], serObj);

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
	bool ret = DeserializeVector<Element>("AVector", Element::GetElementName(), mIt, &deserElem);
	this->m_rKey.push_back(deserElem);

	if( !ret ) return ret;

	mIt = serObj.FindMember("BVector");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	ret = DeserializeVector<Element>("BVector", Element::GetElementName(), mIt, &deserElem);
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

	SerializeVector<Element>("Vectors", Element::GetElementName(), this->GetAVector(), serObj);

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
	if( DeserializeVector<Element>("Vectors", Element::GetElementName(), it, &newElements) ) {
		this->SetAVector(newElements);
		return true;
	}

	return false;
}


}
