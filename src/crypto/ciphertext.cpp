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
	}

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

}  // namespace lbcrypto ends