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

#ifndef LBCRYPTO_CRYPTO_BV_C
#define LBCRYPTO_CRYPTO_BV_C

#include "bv.h"

namespace lbcrypto {


template <class Element>
LPKeyPair<Element> LPAlgorithmBV<Element>::KeyGen(CryptoContext<Element> cc) const
{
	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	const LPCryptoParametersBV<Element> *cryptoParams = dynamic_cast<const LPCryptoParametersBV<Element> *>( &cc.GetCryptoParameters() );

	if( cryptoParams == 0 )
		throw std::logic_error("Wrong type for crypto parameters in LPAlgorithmBV<Element>::KeyGen");

	if( cryptoParams == 0 )
		throw std::logic_error("Wrong type for crypto parameters in LPAlgorithmBV<Element>::KeyGen");

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	const DiscreteUniformGenerator dug(elementParams.GetModulus());

	//Generate the element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	//Generate the secret key
	Element s(dgg, elementParams, Format::COEFFICIENT);
	s.SwitchFormat();

	kp.secretKey->SetPrivateElement(s);

	//public key is generated and set
	//privateKey->MakePublicKey(a, publicKey);
	Element e(dgg, elementParams, Format::COEFFICIENT);
	e.SwitchFormat();

	Element b = a*s + p*e;

	kp.publicKey->SetPublicElementAtIndex(0, std::move(a));
	kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

	return kp;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmBV<Element>::Encrypt(const LPPublicKey<Element> &pubKey,
	const Element &plaintext) const
{

	const LPCryptoParametersBV<Element> *cryptoParams =
		dynamic_cast<const LPCryptoParametersBV<Element>*>(&pubKey.GetCryptoParameters());

	const LPPublicKey<Element> *publicKey =
		dynamic_cast<const LPPublicKey<Element>*>(&pubKey);

	if( cryptoParams == 0 ) return shared_ptr<Ciphertext<Element>>();

	shared_ptr<Ciphertext<Element>> ciphertext( new Ciphertext<Element>(pubKey.GetCryptoContext()) );

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	//const Element &a = publicKey->GetPublicElement();
	const Element &a = publicKey->GetPublicElements().at(0);
	const Element &b = publicKey->GetPublicElements().at(1);

	Element v(dgg, elementParams, Format::EVALUATION);
	Element e0(dgg, elementParams, Format::EVALUATION);
	Element e1(dgg, elementParams, Format::EVALUATION);

	Element c1(elementParams);
	Element c2(elementParams);

	//c1 = b v + p e_0 + m
	c1 = b*v + p*e0 + plaintext;

	//c2 = a v + p e_1
	c2 = a*v + p*e1;

	ciphertext->SetElements({ c1,c2 });

	return ciphertext;
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

template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmPREBV<Element>::ReKeyGen(const shared_ptr<LPKey<Element>> newSK,
	const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
{
	// create a new ReKey of the proper type, in this context
	shared_ptr<LPEvalKeyNTRURelin<Element>> EK( new LPEvalKeyNTRURelin<Element>(newSK->GetCryptoContext()) );

	const LPCryptoParametersBV<Element> *cryptoParamsLWE = dynamic_cast<const LPCryptoParametersBV<Element>*>(&newSK->GetCryptoParameters());

//	if( cryptoParamsLWE == 0 ) {
//		throw std::logic_error("Secret Key crypto parameters have incorrect type in LPAlgorithmPREBV<Element>::ReKeyGen");
//	}

	const ElemParams &elementParams = cryptoParamsLWE->GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();
	const Element &s = origPrivateKey.GetPrivateElement();

	const LPPrivateKey<Element> *newPrivateKey =
		dynamic_cast<const LPPrivateKey<Element>*>(*newSK);

//	if( newPrivateKey == 0 ) {
//		throw std::logic_error("Secret Key has incorrect type in LPAlgorithmPREBV<Element>::ReKeyGen");
//	}

	//LPEvalKeyBV<Element> *evalKey = dynamic_cast<LPEvalKeyBV<Element>*>(EK);

	const Element &sNew = newPrivateKey->GetPrivateElement();

	const DiscreteGaussianGenerator &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	const DiscreteUniformGenerator dug(elementParams.GetModulus());

	//std::vector<Element> *evalKeyElements = &evalKey->AccessEvalKeyElements();
	//std::vector<Element> *evalKeyElementsGenerated = &evalKey->AccessEvalKeyElementsGenerated();
	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));
	std::vector<Element> evalKeyElementsGenerated;

	

	//s.PowersOfBase(relinWindow, evalKeyElements);

	for (usint i = 0; i < (evalKeyElements.size()); i++)
	{
		// Generate a_i vectors
		Element a(dug, elementParams, Format::EVALUATION);
		evalKeyElementsGenerated.push_back(a);

		// Generate a_i * newSK + p * e - PowerOfBase(oldSK)
		Element e(dgg, elementParams, Format::EVALUATION);
		evalKeyElements.at(i) -= (a*sNew + p*e);
		evalKeyElements.at(i) *= (elementParams.GetModulus() - BigBinaryInteger::ONE);

	}

	EK->SetAVector(std::move(evalKeyElements));
	EK->SetBVector(std::move(evalKeyElementsGenerated));

	return EK;

}

//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmPREBV<Element>::ReEncrypt(const LPEvalKey<Element> &EK,
	const Ciphertext<Element> &ciphertext) const
{
	shared_ptr<Ciphertext<Element>> newCiphertext( new Ciphertext<Element>(ciphertext) );

	const LPCryptoParametersBV<Element> *cryptoParamsLWE = dynamic_cast<const LPCryptoParametersBV<Element>*>(&EK.GetCryptoParameters());

	const ElemParams &elementParams = cryptoParamsLWE->GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();

	const LPEvalKeyRelin<Element> &evalKey =
		dynamic_cast<const LPEvalKeyRelin<Element>&>(EK);

	const std::vector<Element> &b = evalKey.GetAVector();
	const std::vector<Element> &a = evalKey.GetBVector();

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	const std::vector<Element> &c = ciphertext.GetElements();

	std::vector<Element> digitsC1;
	c[1].BaseDecompose(relinWindow, &digitsC1);

	// c0' = c0 + \sum\limits_{i}{c_1*b}_i 
	// c1' = \sum\limits_{i}{c_1*a}_i 
	Element ct0(c[0] + digitsC1[0]*b[0]);
	Element ct1(digitsC1[0]*a[0]);

	for (usint i = 1; i < digitsC1.size(); ++i)
	{
		ct0 += digitsC1[i] * b[i];
		ct1 += digitsC1[i] * a[i];
	}

	newCiphertext->SetElements({ct0, ct1});
	return newCiphertext;
}

// Constructor for LPPublicKeyEncryptionSchemeBV
template <class Element>
LPPublicKeyEncryptionSchemeBV<Element>::LPPublicKeyEncryptionSchemeBV(std::bitset<FEATURESETSIZE> mask)
	: LPPublicKeyEncryptionScheme<Element>() {

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmBV<Element>(*this);
	
	if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPREBV<Element>(*this);
	/*if (mask[EVALADD])
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
	case PRE:
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREBV<Element>(*this);
		break;
	/*case EVALADD:
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
