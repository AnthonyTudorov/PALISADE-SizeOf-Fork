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
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Ciphertext<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

		std::unordered_map <std::string, std::string> idFlagMap;
		idFlagMap.emplace("ID", "Ciphertext");
		idFlagMap.emplace("Flag", flag);
		serializationMap.emplace("Root", idFlagMap);

		return serializationMap;
	}

	// JSON FACILITY - Serialize Operation
	template <class Element>
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Ciphertext<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

		serializationMap = this->SetIdFlag(serializationMap, fileFlag);

		const LPCryptoParameters<Element> *lpCryptoParams = &this->GetCryptoParameters();
		serializationMap = lpCryptoParams->Serialize(serializationMap, "");

		std::unordered_map <std::string, std::string> rootMap = serializationMap["Root"];
		serializationMap.erase("Root");
		rootMap.emplace("Norm", this->GetNorm().ToString());
		serializationMap.emplace("Root", rootMap);

		serializationMap = this->GetElement().Serialize(serializationMap, "");

		return serializationMap;
	}

	// JSON FACILITY - Deserialize Operation
	template <class Element>
	void Ciphertext<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

		LPCryptoParameters<Element> *json_cryptoParams = new LPCryptoParametersStehleSteinfeld<Element>();
		json_cryptoParams->Deserialize(serializationMap);
		this->SetCryptoParameters(*json_cryptoParams);

		std::unordered_map<std::string, std::string> rootMap = serializationMap["Root"];
		BigBinaryInteger bbiNorm(rootMap["Norm"]);
		this->SetNorm(bbiNorm);

		Element json_ilElement;
		json_ilElement.Deserialize(serializationMap);
		this->SetElement(json_ilElement);
	}

}  // namespace lbcrypto ends
