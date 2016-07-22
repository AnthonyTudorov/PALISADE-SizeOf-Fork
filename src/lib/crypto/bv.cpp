//LAYER 3 : CRYPTO DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/14/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
		Nishanth Pasham, np386@njit.edu
		Hadi Sajjadpour, ss2959@njit.edu
		Jerry Ryan, gwryan@njit.edu
Description:	

 This code implements the Brakerski-Vaikuntanathan (BV) homomorphic encryption scheme.
 The scheme is described at http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf (or alternative Internet source:
 http://dx.doi.org/10.1007/978-3-642-22792-9_29). Implementation details are provided in
 {the link to the ACM TISSEC manuscript to be added}.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef LBCRYPTO_CRYPTO_LWECRYPT_C
#define LBCRYPTO_CRYPTO_LWECRYPT_C

#include "../crypto/cryptocontext.h"
#include <cstring>
#include <iostream>
#include <fstream>

namespace lbcrypto {

template <class Element>
void LPPrivateKeyBV<Element>::MakePublicKey(const Element &a, LPPublicKey<Element> *pub) const
{
	const LPCryptoParametersRLWE<Element> *cryptoParams =
		dynamic_cast<const LPCryptoParametersRLWE<Element>*>(&this->GetCryptoParameters());

	LPPublicKeyBV<Element> *publicKey =
		dynamic_cast<LPPublicKeyBV<Element>*>(pub);

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	Element e(dgg, elementParams, Format::EVALUATION);

	Element b = a*m_sk + p*e;

	publicKey->SetPublicElements({ a,b });
}

template <class Element>
bool LPAlgorithmBV<Element>::KeyGen(LPPublicKey<Element> *publicKey,
	LPPrivateKey<Element> *privateKey) const
{

	if (publicKey == 0 || privateKey == 0)
		return false;

	const LPCryptoParametersRLWE<Element> *cryptoParams =
		dynamic_cast<const LPCryptoParametersRLWE<Element>*>(&privateKey->GetCryptoParameters());

	if (cryptoParams == 0)
		return false;

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	const DiscreteUniformGenerator dug(elementParams.GetModulus());

	//Generate the element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	//Generate the secret key
	Element s(dgg, elementParams, Format::EVALUATION);

	privateKey->SetPrivateElement(s);
	privateKey->AccessCryptoParameters() = *cryptoParams;

	//public key is generated and set
	privateKey->MakePublicKey(a, publicKey);

	return true;

}

template <class Element>
EncryptResult LPAlgorithmBV<Element>::Encrypt(const LPPublicKey<Element> &pubKey,
	const Element &plaintext,
	Ciphertext<Element> *ciphertext) const
{

	const LPCryptoParametersRLWE<Element> *cryptoParams =
		dynamic_cast<const LPCryptoParametersRLWE<Element>*>(&pubKey.GetCryptoParameters());

	const LPPublicKeyBV<Element> *publicKey =
		dynamic_cast<const LPPublicKeyBV<Element>*>(&pubKey);

	if (cryptoParams == 0) return EncryptResult();

	if (ciphertext == 0) return EncryptResult();

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	const Element &a = publicKey->GetPublicElement();
	const Element &b = publicKey->GetGeneratedPublicElement();

	Element v(dgg, elementParams, Format::EVALUATION);
	Element e0(dgg, elementParams, Format::EVALUATION);
	Element e1(dgg, elementParams, Format::EVALUATION);

	Element c1(elementParams);
	Element c2(elementParams);

	//c1 = b v + p e_0 + m
	c1 = b*v + p*e0 + plaintext;

	//c2 = a v + p e_1
	c2 = a*v + p*e1;

	ciphertext->SetCryptoParameters(cryptoParams);
	ciphertext->SetPublicKey(pubKey);
	ciphertext->SetEncryptionAlgorithm(this->GetScheme());
	ciphertext->SetElements({ c1,c2 });

	return EncryptResult(0);
}

template <class Element>
DecryptResult LPAlgorithmBV<Element>::Decrypt(const LPPrivateKey<Element> &privateKey,
	const Ciphertext<Element> &ciphertext,
	Element *plaintext) const
{

	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	const std::vector<Element> &c = ciphertext.GetElements();

	const Element &s = privateKey.GetPrivateElement();

	Element b = c[0] - s*c[1];

	b.SwitchFormat();
	
	*plaintext = b;

	return DecryptResult(plaintext->GetLength());

}


// Constructor for LPPublicKeyEncryptionSchemeBV
template <class Element>
LPPublicKeyEncryptionSchemeBV<Element>::LPPublicKeyEncryptionSchemeBV(std::bitset<FEATURESETSIZE> mask, size_t chunksize)
	: LPPublicKeyEncryptionScheme<Element>(chunksize) {

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmBV<Element>(*this);
	/*
	if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>(*this);
	if (mask[EVALADD])
		this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
	if (mask[EVALAUTOMORPHISM])
		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
	if (mask[SHE])
		this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
	if (mask[FHE])
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);
	if (mask[LEVELEDSHE])
		this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>(*this);
	*/

}

// Enable for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeBV<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBV<Element>(*this);
		break;
	/*case PRE:
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>(*this);
		break;
	case EVALADD:
		if (this->m_algorithmEvalAdd == NULL)
			this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
		break;
	case EVALAUTOMORPHISM:
		if (this->m_algorithmEvalAutomorphism == NULL)
			this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
		break;
	case SHE:
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
		break;
	case FHE:
		if (this->m_algorithmFHE == NULL)
			this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);
		break;
	case LEVELEDSHE:
		if (this->m_algorithmLeveledSHE == NULL)
			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>(*this);
		break;
		*/
	}
}

}  // namespace lbcrypto ends

#endif
