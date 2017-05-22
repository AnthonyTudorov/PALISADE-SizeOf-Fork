/*
 * ciphertext.cpp
 *
 *  Created on: May 21, 2017
 *      Author: gerardryan
 */

#include "ciphertext.h"

namespace lbcrypto {

template <typename Element>
bool Ciphertext<Element>::Serialize(Serialized* serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "Ciphertext", serObj->GetAllocator());

	if( !this->GetCryptoParameters()->Serialize(serObj) )
		return false;

	SerializeVector("Elements", this->m_elements[0].GetElementName(), this->m_elements, serObj);

	return true;
}

template <typename Element>
bool Ciphertext<Element>::Deserialize(const Serialized& serObj) {
	// deserialization must be done in a crypto context; this object must be initialized before deserializing the elements
	if( !this->cryptoContext )
		return false;

	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Ciphertext" )
		return false;

	mIter = serObj.FindMember("Elements");
	if( mIter == serObj.MemberEnd() )
		return false;

	return DeserializeVector<Element>("Elements", this->m_elements[0].GetElementName(), mIter, &this->m_elements);
}

}
