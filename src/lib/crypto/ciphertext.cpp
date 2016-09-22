//LAYER 3 : CIPHERTEXT REPRESENTATION
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Hadi Sajjadpour <ss2959@njit.edu>
Description:	
	This code provides the core proxy re-encryption functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef _SRC_LIB_CRYPTO_CRYPTOCONTEXT_C
#define _SRC_LIB_CRYPTO_CRYPTOCONTEXT_C

#include "ciphertext.h"
#include "../utils/serializablehelper.h"
#include "cryptocontext.h"

namespace lbcrypto {

// copy constructor
template <class Element>
Ciphertext<Element>::Ciphertext(const Ciphertext<Element> &ciphertext) {
	cryptoContext = ciphertext.cryptoContext;
	m_norm = ciphertext.m_norm;
	m_elements = ciphertext.m_elements;
}

// move constructor
template <class Element>
Ciphertext<Element>::Ciphertext(Ciphertext<Element> &&ciphertext) {
	cryptoContext = ciphertext.cryptoContext;
	m_norm = ciphertext.m_norm;
	m_elements = ciphertext.m_elements;
}

// assignment operator
template <class Element>
Ciphertext<Element>& Ciphertext<Element>::operator=(const Ciphertext<Element> &rhs)
{
	if (this != &rhs) {
		this->cryptoContext = rhs.cryptoContext;
		this->m_norm = rhs.m_norm;
		this->m_elements = rhs.m_elements;
	}

	return *this;
}

// moveable assignment operator
template <class Element>
Ciphertext<Element>& Ciphertext<Element>::operator=(Ciphertext<Element> &&rhs)
{
	if (this != &rhs) {
		this->cryptoContext = rhs.cryptoContext;
		this->m_norm = rhs.m_norm;
		this->m_elements = rhs.m_elements;
	}

	return *this;
}

// EvalAdd Operation
template <class Element>
Ciphertext<Element> Ciphertext<Element>::EvalAdd(const Ciphertext<Element> &ciphertext) const
{
	if(this->cryptoContext != ciphertext.cryptoContext){
		std::string errMsg = "EvalAdd: CryptoParameters of added the ciphertexts are the not the same.";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<Element> sum(*this);

	//YSP this should be optimized to use the in-place += operator
	for (int i = 0; i < this->m_elements.size(); i++)
	{
		sum.m_elements[i] = this->m_elements[i] + ciphertext.m_elements[i];
	}
	return sum;
}

// JSON FACILITY - SetIdFlag Operation
template <class Element>
bool Ciphertext<Element>::SetIdFlag(Serialized* serObj, const std::string flag) const {

	SerialItem idFlagMap(rapidjson::kObjectType);
	idFlagMap.AddMember("ID", "Ciphertext", serObj->GetAllocator());
	idFlagMap.AddMember("Flag", flag, serObj->GetAllocator());

	serObj->AddMember("Root", idFlagMap, serObj->GetAllocator());

	return true;
}

// JSON FACILITY - Serialize Operation

template <class Element>
bool Ciphertext<Element>::Serialize(Serialized* serObj, const std::string fileFlag) const {

	serObj->SetObject();
	if( !this->SetIdFlag(serObj, fileFlag) )
		return false;

	if( !this->GetCryptoParameters().Serialize(serObj) )
		return false;

	serObj->AddMember("Norm", this->GetNorm().ToString(), serObj->GetAllocator());

	Serialized serElements(rapidjson::kObjectType, &serObj->GetAllocator());
	const std::vector<Element>& elements = this->GetElements();
	int vecsize = elements.size();
	serObj->AddMember("VectorSize", std::to_string(vecsize), serObj->GetAllocator());

	if( vecsize > 0 ) {
		std::string elementTypeName;
		if( typeid(Element) == typeid(ILVector2n) ) {
			elementTypeName = "ILVector2n";
		} else if( typeid(Element) == typeid(ILVectorArray2n) ) {
			elementTypeName = "ILVectorArray2n";
		} else {
			throw std::logic_error("Unrecognized element type in this Ciphertext");
		}

		serObj->AddMember("VectorElementType", elementTypeName, serObj->GetAllocator());

		for( int i=0; i<vecsize; i++ ) {
			Serialized oneEl(rapidjson::kObjectType, &serObj->GetAllocator());
			this->GetElements().at(i).Serialize(&oneEl);

			SerialItem key( std::to_string(i), serObj->GetAllocator() );
			serElements.AddMember(key, oneEl.Move(), serObj->GetAllocator());
		}

		serObj->AddMember("Elements", serElements.Move(), serObj->GetAllocator());
	}

	return true;
}

// JSON FACILITY - Deserialize Operation
//template <class Element>
//bool Ciphertext<Element>::Deserialize(const Serialized& serObj, const CryptoContext<Element>* ctx) {

//	LPCryptoParameters<Element>* cryptoParams = DeserializeAndValidateCryptoParameters<Element>(serObj, *ctx->getParams());
//	if( cryptoParams == 0 ) return false;
//
//	Serialized::ConstMemberIterator mIter = serObj.FindMember("Root");
//	if( mIter == serObj.MemberEnd() )
//		return false;
//
//	Serialized::ConstMemberIterator normIter = serObj.FindMember("Norm");
//	if( normIter == serObj.MemberEnd() )
//		return false;
//
//	BigBinaryInteger bbiNorm(normIter->value.GetString());
//
//	Serialized::ConstMemberIterator sizeIter = serObj.FindMember("VectorSize");
//	if( sizeIter == serObj.MemberEnd() )
//		return false;
//
//	int nElements = std::stoi(sizeIter->value.GetString());
//	std::vector<Element> elements(nElements);
//
//	Serialized::ConstMemberIterator typeIter = serObj.FindMember("VectorElementType");
//	if( typeIter == serObj.MemberEnd() )
//		return false;
//
//	std::string elType = typeIter->value.GetString();
//
//	if( typeid(Element) == typeid(ILVector2n) && elType != "ILVector2n" ) {
//		throw std::logic_error("Serialization Element type does not match this Ciphertext");
//	} else if( typeid(Element) == typeid(ILVectorArray2n) && elType != "ILVectorArray2n" ) {
//		throw std::logic_error("Serialization Element type does not match this Ciphertext");
//	}
//
//	Serialized::ConstMemberIterator elVec = serObj.FindMember("Elements");
//	if( elVec == serObj.MemberEnd() )
//		return false;
//
//	for( int i=0; i<nElements; i++ ) {
//		SerialItem::ConstMemberIterator elIter = elVec->value.FindMember( std::to_string(i) );
//		if( elIter == elVec->value.MemberEnd() ) {
//			return false;
//		}
//
//		Serialized::ConstMemberIterator findEl = elIter->value.FindMember( elType );
//		if( findEl == elIter->value.MemberEnd() ) {
//			return false;
//		}
//
//		Serialized el(rapidjson::kObjectType);
//		el.AddMember(SerialItem(elType,el.GetAllocator()), SerialItem(findEl->value,el.GetAllocator()), el.GetAllocator());
//		Element json_ilElement;
//		if( !json_ilElement.Deserialize( el ) )
//			return false;
//
//		elements[i] = json_ilElement;
//	}
//
//	this->m_cryptoParameters = cryptoParams;
//	this->SetNorm(bbiNorm);
//	this->SetElements(elements);
//
//	return true;
//	return false;
//}

}  // namespace lbcrypto ends

#endif
