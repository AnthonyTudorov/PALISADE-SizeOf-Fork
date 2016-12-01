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

template <class Element>
bool Ciphertext<Element>::Serialize(Serialized* serObj) const
{
	serObj->SetObject();

	serObj->AddMember("Object", "Ciphertext", serObj->GetAllocator());

	if( !this->GetCryptoParameters()->Serialize(serObj) )
		return false;

	serObj->AddMember("Norm", this->GetNorm().ToString(), serObj->GetAllocator());

	SerializeVector("Elements", elementName<Element>(), this->m_elements, serObj);

	return true;
}

template <class Element>
bool Ciphertext<Element>::Deserialize(const Serialized& serObj)
{
	// deserialization must be done in a crypto context; this object must be initialized before deserializing the elements
	if( !this->cryptoContext )
		return false;

	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Ciphertext" )
		return false;

	mIter = serObj.FindMember("Norm");
	if( mIter == serObj.MemberEnd() )
		return false;

	BigBinaryInteger bbiNorm(mIter->value.GetString());

	mIter = serObj.FindMember("Elements");
	if( mIter == serObj.MemberEnd() )
		return false;

	return DeserializeVector<Element>("Elements", elementName<Element>(), mIter, &this->m_elements);
}

}  // namespace lbcrypto ends

#endif
