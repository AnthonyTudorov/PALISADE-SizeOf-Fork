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
	This code provides the core proxy re-encryption functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef _SRC_LIB_CRYPTO_LWECRYPT_C
#define _SRC_LIB_CRYPTO_LWECRYPT_C

#include "../crypto/cryptocontext.h"
#include <cstring>
#include <iostream>
#include <fstream>
#include <initializer_list>

namespace lbcrypto {

template <class Element>
bool LPAlgorithmLTV<Element>::KeyGen(LPPublicKey<Element> *publicKey, 
		LPPrivateKey<Element> *privateKey) const
{

	if( publicKey == 0 || privateKey == 0 )
		return false;

	const LPCryptoParametersLTV<Element> *pubKeyCp =
			dynamic_cast<const LPCryptoParametersLTV<Element>*>(&publicKey->GetCryptoParameters());

	if( pubKeyCp == 0 )
		throw std::logic_error("Public Key must use LTV parameters of type LPCryptoParametersLTV");

	const LPCryptoParametersLTV<Element> *cryptoParams =
			dynamic_cast<const LPCryptoParametersLTV<Element>*>(&privateKey->GetCryptoParameters());

	if( cryptoParams == 0 )
		throw std::logic_error("Private Key must use LTV parameters of type LPCryptoParametersLTV");

//	if( *pubKeyCp != *cryptoParams )
//		throw std::logic_error("Public and Private Key must use same crypto parameters");

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;

	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
		Element temp(dgg, elementParams, Format::COEFFICIENT);
		f = temp;
		f = p*f;
		f = f + BigBinaryInteger::ONE;
		f.SwitchFormat();
	}

	privateKey->SetPrivateElement(f);

	Element g(dgg,elementParams,Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	publicKey->SetPublicElementAtIndex(0, std::move(cryptoParams->GetPlaintextModulus()*g*privateKey->GetPrivateElement().MultiplicativeInverse()));

	return true;
}


template <class Element>
bool LPEncryptionAlgorithmStehleSteinfeld<Element>::KeyGen(LPPublicKey<Element> *publicKey, 
		LPPrivateKey<Element> *privateKey) const
		{
	if( publicKey == 0 || privateKey == 0 )
		return false;

	const LPCryptoParametersStehleSteinfeld<Element> *cryptoParams =
			dynamic_cast<const LPCryptoParametersStehleSteinfeld<Element>*>(&privateKey->GetCryptoParameters());

	if( cryptoParams == 0 )
		return false;

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGeneratorStSt();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;

	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
		//std::cout << "inverse does not exist" << std::endl;
		Element temp(dgg, elementParams, Format::COEFFICIENT);
		f = temp;
		f = p*f;
		f = f + BigBinaryInteger::ONE;
		f.SwitchFormat();
	}

	privateKey->SetPrivateElement(f);

	Element g(dgg,elementParams,Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	publicKey->SetPublicElementAtIndex(0, cryptoParams->GetPlaintextModulus()*g*privateKey->GetPrivateElement().MultiplicativeInverse());

	return true;
}

/**
* Method for KeySwitching based on a KeySwitchHint
*
* This function Calculates a  KeySwitchHint. The hint is used to convert a ciphertext encrypted with 
* private key A to a ciphertext that is decryptable by the public key of B. 
* The algorithm can be found from this paper.
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
* 
* KeySwitchHint 
*/
template<class Element>
void LPLeveledSHEAlgorithmLTV<Element>::EvalMultKeyGen(const LPPrivateKey<Element> &originalPrivateKey, 
				const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *keySwitchHint) const {  

		const LPCryptoParametersLTV<Element> &cryptoParams = dynamic_cast<const LPCryptoParametersLTV<Element> &>(originalPrivateKey.GetCryptoParameters() );

		const ElemParams &originalKeyParams = cryptoParams.GetElementParams() ;

		const Element f1 = originalPrivateKey.GetPrivateElement(); //add const
		const Element f2 = newPrivateKey.GetPrivateElement(); //add const
		const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

		Element e(cryptoParams.GetDiscreteGaussianGenerator() , originalKeyParams, Format::COEFFICIENT );
		
		e.SwitchFormat();

		Element m(p*e);
		
		m.AddILElementOne();

		Element newKeyInverse = f2.MultiplicativeInverse(); 

		Element keySwitchHintElement(m * f1 * newKeyInverse);

		/*keySwitchHintElement = m * f1 * newKeyInverse ;*/
		keySwitchHint->SetA(std::move(keySwitchHintElement));
}
			
/*
* Method for KeySwitching based on a KeySwitchHint
*
* This function performs KeySwitch based on a KeySwitchHint. 
* The algorithm can be found from this paper:
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
* 
*KeySwitch takes in a KeySwitchHint and a cipher text. Based on the two, it calculates and returns a new ciphertext. 
* if the KeySwitchHint is constructed for Private Key A converted to Private Key B, then the new ciphertext, originally encrypted with
* private key A, is now decryptable by public key B (and not A).
*/
template<class Element>
Ciphertext<Element> LPLeveledSHEAlgorithmLTV<Element>::KeySwitch(const LPEvalKey<Element> &keySwitchHint,const Ciphertext<Element> &cipherText) const {

	//Get the EvalKeyNTRU to perform key swich, also verfies if proper EvalKey is instantiated.
	const LPEvalKeyNTRU<Element> &keyHint = dynamic_cast<const LPEvalKeyNTRU<Element>&>(keySwitchHint);

	Ciphertext<Element> newCipherText(cipherText);

	Element newCipherTextElement = cipherText.GetElement()*keyHint.GetA();

	newCipherText.SetElement( newCipherTextElement );
	
	return newCipherText ;
}


/*Generates a keyswitchhint from originalPrivateKey^(2) to newPrivateKey */
template<class Element>
void LPLeveledSHEAlgorithmLTV<Element>::QuadraticEvalMultKeyGen(const LPPrivateKey<Element> &originalPrivateKey, 
	
	const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *quadraticKeySwitchHint) const {

	const LPCryptoParametersLTV<Element> &cryptoParams = dynamic_cast<const LPCryptoParametersLTV<Element> &>(originalPrivateKey.GetCryptoParameters() );

	const ElemParams &originalKeyParams = cryptoParams.GetElementParams() ;

	const Element f1 = originalPrivateKey.GetPrivateElement(); //add const

	const Element f1Squared(f1*f1); //squaring the key
	const Element f2 = newPrivateKey.GetPrivateElement(); //add const
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element e(cryptoParams.GetDiscreteGaussianGenerator() , originalKeyParams, Format::COEFFICIENT );

	e.SwitchFormat();

	Element m(p*e);

	m = p * e;
	
	m.AddILElementOne();

	Element newKeyInverse = f2.MultiplicativeInverse(); 

	Element keySwitchHintElement(m * f1Squared * newKeyInverse);

	quadraticKeySwitchHint->SetA(keySwitchHintElement);
}

/**
* Method for ModReducing on any Element datastructure-TODO
*/
template<class Element>
void LPLeveledSHEAlgorithmLTV<Element>::ModReduce(Ciphertext<Element> *cipherText) const {
	
}

/**
* This function performs ModReduce on ciphertext element and private key element. The algorithm can be found from this paper:
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
* 
* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus q/qi. The qi is generally the largest. In the code below,
* ModReduce is written for ILVectorArray2n and it drops the last tower while updating the necessary parameters. 
*/
template<> inline
void LPLeveledSHEAlgorithmLTV<ILVectorArray2n>::ModReduce(Ciphertext<ILVectorArray2n> *cipherText) const {

	ILVectorArray2n cipherTextElement(cipherText->GetElement()); 

	BigBinaryInteger plaintextModulus(cipherText->GetCryptoParameters().GetPlaintextModulus());

	cipherTextElement.ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.

	cipherText->SetElement(cipherTextElement);
	
}

/**
* This function performs RingReduce on ciphertext element and private key element. The algorithm can be found from this paper:
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
* The paper quoted above has an algorithm for generic RingReduce, the code here only reduces the ring by a factor of 2. By the ring, we mean the ring dimension.
* @Input params are cipherText and privateKey, output cipherText element is ring reduced by a factor of 2
* 
*/
template<class Element>
void LPLeveledSHEAlgorithmLTV<Element>::RingReduce(Ciphertext<Element> *cipherText, const LPEvalKeyNTRU<Element> &keySwitchHint) const {

		//KeySwitching to a cipherText that can be decrypted by a sparse key. 
		*cipherText = this->KeySwitch( keySwitchHint, *cipherText) ;

		//Once the keyswitching of the ciphertext has been done, based on the algorithm in the referenced paper, the ciphertext needs to be decomposed.
		Element keySwitchedCipherTextElement(cipherText->GetElement());
		
		//changing from EVALUATION to COEFFICIENT domain before performing Decompose operation. Decompose is done in coeffiecient domain.
		keySwitchedCipherTextElement.SwitchFormat();

		/*Based on the algorithm their needs to be a decompose done on the ciphertext. The W factor in this function is 2. The decompose is done
		on the elements of keySwitchedCipherTextElement*/
		keySwitchedCipherTextElement.Decompose();		

		//Converting back to EVALUATION representation.
		keySwitchedCipherTextElement.SwitchFormat();

		//setting the decomposed element into ciphertext.
		cipherText->SetElement(keySwitchedCipherTextElement);

		//Modifying the cipherText crypto parameters to account for changes in cipherText Element.
		//const LPCryptoParametersLTV<Element> &cryptoParams = dynamic_cast<const LPCryptoParametersLTV<Element>&>(cipherText->GetCryptoParameters());
		//ElemParams elementParams(cryptoParams.GetElementParams());
		
}

template<class Element>
void LPLeveledSHEAlgorithmLTV<Element>::ComposedEvalMult(const Ciphertext<Element> &cipherText1, const Ciphertext<Element> &cipherText2, const LPEvalKeyNTRU<Element> &quadKeySwitchHint, Ciphertext<Element> *cipherTextResult) const {

	if(!(cipherText1.GetCryptoParameters() == cipherText2.GetCryptoParameters()) || !(cipherTextResult->GetCryptoParameters() == cipherText2.GetCryptoParameters())){
		std::string errMsg = "ComposedEvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	const LPPublicKeyEncryptionSchemeLTV<Element> &scheme = dynamic_cast< const LPPublicKeyEncryptionSchemeLTV<Element> &>( this->GetScheme() );

	//scheme.m_algorithmSHE->EvalMult(cipherText1,cipherText2, cipherTextResult);
	scheme.EvalMult(cipherText1,cipherText2, cipherTextResult);

	//*cipherTextResult = scheme.m_algorithmLeveledSHE->KeySwitch(quadKeySwitchHint,*cipherTextResult);
	*cipherTextResult = scheme.KeySwitch(quadKeySwitchHint,*cipherTextResult);

	//scheme.m_algorithmLeveledSHE->ModReduce(cipherTextResult);
	scheme.ModReduce(cipherTextResult);
	
}

template<class Element>
void LPLeveledSHEAlgorithmLTV<Element>::LevelReduce(const Ciphertext<Element> &cipherText1, const LPEvalKeyNTRU<Element> &linearKeySwitchHint, Ciphertext<Element> *cipherTextResult) const {

	if(!(cipherText1.GetCryptoParameters() == cipherTextResult->GetCryptoParameters())){
		std::string errMsg = "LevelReduce crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}
	
	const LPPublicKeyEncryptionSchemeLTV<Element> &scheme = dynamic_cast< const LPPublicKeyEncryptionSchemeLTV<Element> &>( this->GetScheme() );

	//*cipherTextResult = scheme.m_algorithmLeveledSHE->KeySwitch(linearKeySwitchHint,cipherText1);
	*cipherTextResult = scheme.KeySwitch(linearKeySwitchHint,cipherText1);

	scheme.ModReduce(cipherTextResult);

}

template<class Element>
bool LPLeveledSHEAlgorithmLTV<Element>::SparseKeyGen(LPPublicKey<Element>* publicKey, LPPrivateKey<Element>* privateKey) const
{
	if (publicKey == 0 || privateKey == 0)
		return false;

	const LPCryptoParametersLTV<Element> *cryptoParams =
		dynamic_cast<const LPCryptoParametersLTV<Element>*>(&privateKey->GetCryptoParameters());

	if (cryptoParams == 0)
		return false;

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	Element f(dgg, elementParams, Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;

	f.MakeSparse(BigBinaryInteger::TWO);

	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
		Element temp(dgg, elementParams, Format::COEFFICIENT);
		f = temp;
		f = p*f;
		f = f + BigBinaryInteger::ONE;
		f.MakeSparse(BigBinaryInteger::TWO);
		f.SwitchFormat();
	}

	privateKey->SetPrivateElement(f);

	Element g(dgg, elementParams, Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	publicKey->SetPublicElementAtIndex(0, std::move(cryptoParams->GetPlaintextModulus()*g*privateKey->GetPrivateElement().MultiplicativeInverse()));

	return true;
}

template<class Element>
bool LPLeveledSHEAlgorithmLTV<Element>::CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const
{
	if (ringDimension == 1) return false;
	ringDimension = ringDimension / 2;
	double multipliedModuli = 1;

	for (usint i = 0; i < moduli.size(); i++) {
		multipliedModuli = multipliedModuli*  moduli.at(i).ConvertToDouble();
	}
	double powerValue = (log(multipliedModuli) / log(2)) / (4 * ringDimension);
	double powerOfTwo = pow(2, powerValue);

	return rootHermiteFactor >= powerOfTwo;
}

template <class Element>
EncryptResult LPAlgorithmLTV<Element>::Encrypt(const LPPublicKey<Element> &publicKey,
		const Element &plaintext,
		Ciphertext<Element> *ciphertext) const
{

	const LPCryptoParametersRLWE<Element> *cryptoParams =
			dynamic_cast<const LPCryptoParametersRLWE<Element>*>(&publicKey.GetCryptoParameters());

	if( cryptoParams == 0 ) return EncryptResult();

	if( ciphertext == 0 ) return EncryptResult();

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	const Element &h = publicKey.GetPublicElements().at(0);

	Element s(dgg,elementParams);

	Element e(dgg,elementParams);

	Element c(elementParams);

	c = h*s + p*e + plaintext;

	ciphertext->SetCryptoParameters(cryptoParams);
	ciphertext->SetEncryptionAlgorithm(this->GetScheme());
	ciphertext->SetElement(c);

	return EncryptResult(0);
}

template <class Element>
DecryptResult LPAlgorithmLTV<Element>::Decrypt(const LPPrivateKey<Element> &privateKey, 
		const Ciphertext<Element> &ciphertext,
		Element *plaintext) const
		{

	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element c( ciphertext.GetElement() );

	Element f = privateKey.GetPrivateElement(); //add const

	Element b = f*c;

	b.SwitchFormat();
	
	*plaintext = b;

	return DecryptResult(plaintext->GetLength());
}






// Default constructor for LPPublicKeyEncryptionSchemeLTV
/*template <class Element>
LPPublicKeyEncryptionSchemeLTV<Element>::LPPublicKeyEncryptionSchemeLTV(){
	this->m_algorithmEncryption = NULL;
	this->m_algorithmPRE = NULL;
	this->m_algorithmEvalAdd = NULL;
	this->m_algorithmEvalAutomorphism = NULL;
	this->m_algorithmSHE = NULL;
	this->m_algorithmFHE = NULL;
	this->m_algorithmLeveledSHE = NULL;
}
*/

// Constructor for LPPublicKeyEncryptionSchemeLTV
template <class Element>
LPPublicKeyEncryptionSchemeLTV<Element>::LPPublicKeyEncryptionSchemeLTV(std::bitset<FEATURESETSIZE> mask)
: LPPublicKeyEncryptionScheme<Element>() {

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmLTV<Element>(*this);
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

}

// Enable for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeLTV<Element>::Enable(PKESchemeFeature feature){
	switch (feature)
	{
	case ENCRYPTION:
		if( this->m_algorithmEncryption == NULL )
			this->m_algorithmEncryption = new LPAlgorithmLTV<Element>(*this);
		break;
	case PRE:
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
	}
}

// Constructor for LPPublicKeyEncryptionSchemeStehleSteinfeld
template <class Element>
LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>::LPPublicKeyEncryptionSchemeStehleSteinfeld(std::bitset<FEATURESETSIZE> mask)
	: LPPublicKeyEncryptionSchemeLTV<Element>() {
	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>(*this);
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
}

// Feature enable method for LPPublicKeyEncryptionSchemeStehleSteinfeld
template <class Element>
void LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>::Enable(PKESchemeFeature feature){
	switch (feature)
	{
	case ENCRYPTION:
		if( this->m_algorithmEncryption == NULL )
			this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>(*this);
		break;
	case PRE:
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
	}
}


}  // namespace lbcrypto ends

#endif
