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

#include "ciphertext.h"

namespace lbcrypto {

	// copy constructor
	template <class Element>
	Ciphertext<Element>::Ciphertext(const Ciphertext<Element> &ciphertext) {
		m_cryptoParameters = ciphertext.m_cryptoParameters;
		m_publicKey = ciphertext.m_publicKey;
		m_encryptionAlgorithm = ciphertext.m_encryptionAlgorithm;
		m_norm = ciphertext.m_norm;
		m_element = ciphertext.m_element;
	} //

	// move constructor
	template <class Element>
	Ciphertext<Element>::Ciphertext(Ciphertext<Element> &&ciphertext) {
		m_cryptoParameters = ciphertext.m_cryptoParameters;
		m_publicKey = ciphertext.m_publicKey;
		m_encryptionAlgorithm = ciphertext.m_encryptionAlgorithm;
		m_norm = ciphertext.m_norm;
		m_element = ciphertext.m_element;
	}

	// assignment operator
	template <class Element>
	Ciphertext<Element>& Ciphertext<Element>::operator=(const Ciphertext<Element> &rhs)
	{
		if (this != &rhs) {
			this->m_cryptoParameters = rhs.m_cryptoParameters;
			this->m_publicKey = rhs.m_publicKey;
			this->m_encryptionAlgorithm = rhs.m_encryptionAlgorithm;
			this->m_norm = rhs.m_norm;
			this->m_element = rhs.m_element;
		}

		return *this;
	}

	// moveable assignment operator
	template <class Element>
	Ciphertext<Element>& Ciphertext<Element>::operator=(Ciphertext<Element> &&rhs)
	{
		if (this != &rhs) {
			this->m_cryptoParameters = rhs.m_cryptoParameters;
			this->m_publicKey = rhs.m_publicKey;
			this->m_encryptionAlgorithm = rhs.m_encryptionAlgorithm;
			this->m_norm = rhs.m_norm;
			this->m_element = rhs.m_element;
		}

		return *this;
	}

	// EvalAdd Operation
	template <class Element>
	Ciphertext<Element> Ciphertext<Element>::EvalAdd(const Ciphertext<Element> &ciphertext) const
	{
		Ciphertext<Element> sum(*this);

		sum.m_element = this->m_element + ciphertext.m_element;

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
	//
	// this is an item that is saved to a file
	// note that right now it only saves cryptoParameters, norm and element
	// the Flag could be used to tell us what stuff is and is not saved
	//
	template <class Element>
	bool Ciphertext<Element>::Serialize(Serialized* serObj, const std::string fileFlag) const {

		serObj->SetObject();
		if( !this->SetIdFlag(serObj, "minimal") )
			return false;

		if( !this->GetCryptoParameters().Serialize(serObj, "") )
			return false;

		serObj->AddMember("Norm", this->GetNorm().ToString(), serObj->GetAllocator());

		return this->GetElement().Serialize(serObj, "");
	}

	// JSON FACILITY - Deserialize Operation
	template <class Element>
	bool Ciphertext<Element>::Deserialize(const Serialized& serObj) {

		if( !DeserializeAndSetCryptoParameters<Element,Ciphertext<Element>>(serObj, this) ) return false;

		// yeah this could be done better...
		LPCryptoParameters<Element>* json_cryptoParams = (LPCryptoParameters<Element>*) &this->GetCryptoParameters();

		if( !json_cryptoParams->Deserialize(serObj) )
			return false;

		// for future use, make sure you pick everything out of the serialization that is in there...
		Serialized::ConstMemberIterator mIter = serObj.FindMember("Root");
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized::ConstMemberIterator normIter = serObj.FindMember("Norm");
		if( normIter == mIter->value.MemberEnd() )
			return false;

		BigBinaryInteger bbiNorm(normIter->value.GetString());

		Element json_ilElement;
		if( !json_ilElement.Deserialize(serObj) )
			return false;

		this->SetCryptoParameters(json_cryptoParams);
		this->SetNorm(bbiNorm);
		this->SetElement(json_ilElement);
		return true;
	}

}  // namespace lbcrypto ends
