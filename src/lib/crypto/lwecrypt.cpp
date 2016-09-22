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

#include "lwecrypt.h"

namespace lbcrypto {

template <class Element>
LPKeyPair<Element> LPAlgorithmLTV<Element>::KeyGen(const CryptoContext<Element> cc) const
{
	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersLTV<Element>>(cc.GetCryptoParameters());

//	if( cryptoParams == 0 )
//		throw std::logic_error("Wrong type for crypto parameters in LPAlgorithmLTV<Element>::KeyGen");

	const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGenerator();

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

	kp.secretKey->SetPrivateElement(f);

	Element g(dgg,elementParams,Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	kp.publicKey->SetPublicElementAtIndex(0, std::move(cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse()));

	return kp;
}


template <class Element>
LPKeyPair<Element> LPEncryptionAlgorithmStehleSteinfeld<Element>::KeyGen(const CryptoContext<Element> cc) const
		{
	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	const shared_ptr<LPCryptoParametersStehleSteinfeld<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersStehleSteinfeld<Element>>(cc.GetCryptoParameters());

	const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGeneratorStSt();

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

	kp.secretKey->SetPrivateElement(f);

	Element g(dgg,elementParams,Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	kp.publicKey->SetPublicElementAtIndex(0, cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse());

	return kp;
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
shared_ptr<LPEvalKeyNTRU<Element>> LPLeveledSHEAlgorithmLTV<Element>::EvalMultKeyGen(
		const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
		const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {

		shared_ptr<LPEvalKeyNTRU<Element>> keySwitchHint(new LPEvalKeyNTRU<Element>(originalPrivateKey->GetCryptoContext()));

		const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersLTV<Element>>(originalPrivateKey->GetCryptoParameters() );

		const Element f1 = originalPrivateKey->GetPrivateElement(); //add const
		const Element f2 = newPrivateKey->GetPrivateElement(); //add const
		const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

		Element e(cryptoParams->GetDiscreteGaussianGenerator() , cryptoParams->GetElementParams(), Format::COEFFICIENT );
		
		e.SwitchFormat();

		Element m(p*e);
		
		m.AddILElementOne();

		Element newKeyInverse = f2.MultiplicativeInverse(); 

		Element keySwitchHintElement(m * f1 * newKeyInverse);

		/*keySwitchHintElement = m * f1 * newKeyInverse ;*/
		keySwitchHint->SetA(std::move(keySwitchHintElement));
		return keySwitchHint;
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
shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmLTV<Element>::KeySwitch(
		const shared_ptr<LPEvalKey<Element>> keySwitchHint,
		const shared_ptr<Ciphertext<Element>> cipherText) const {

	//Get the EvalKeyNTRU to perform key swich, also verfies if proper EvalKey is instantiated.
	const shared_ptr<LPEvalKeyNTRU<Element>> keyHint = std::static_pointer_cast<LPEvalKeyNTRU<Element>>(keySwitchHint);

	shared_ptr<Ciphertext<Element>> newCipherText( new Ciphertext<Element>(cipherText->GetCryptoContext()) );

	Element newCipherTextElement = cipherText->GetElement() * keyHint->GetA();

	newCipherText->SetElement( newCipherTextElement );
	
	return newCipherText ;
}


/*Generates a keyswitchhint from originalPrivateKey^(2) to newPrivateKey */
template<class Element>
shared_ptr<LPEvalKeyNTRU<Element>> LPLeveledSHEAlgorithmLTV<Element>::QuadraticEvalMultKeyGen(
	const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
	const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {
	
	shared_ptr<LPEvalKeyNTRU<Element>> quadraticKeySwitchHint( new LPEvalKeyNTRU<Element>(originalPrivateKey->GetCryptoContext()) );

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersLTV<Element>>(originalPrivateKey->GetCryptoParameters() );

	const Element f1 = originalPrivateKey->GetPrivateElement(); //add const

	const Element f1Squared(f1*f1); //squaring the key
	const Element f2 = newPrivateKey->GetPrivateElement(); //add const
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	Element e(cryptoParams->GetDiscreteGaussianGenerator() , cryptoParams->GetElementParams(), Format::COEFFICIENT );

	e.SwitchFormat();

	Element m(p*e);

	m = p * e;
	
	m.AddILElementOne();

	Element newKeyInverse = f2.MultiplicativeInverse(); 

	Element keySwitchHintElement(m * f1Squared * newKeyInverse);

	quadraticKeySwitchHint->SetA(keySwitchHintElement);
	return quadraticKeySwitchHint;
}

///**
//* Method for ModReducing on any Element datastructure-TODO
//*/
//template<class Element>
//void LPLeveledSHEAlgorithmLTV<Element>::ModReduce(Ciphertext<Element> *cipherText) const {
//
//}

/**
* This function performs ModReduce on ciphertext element and private key element. The algorithm can be found from this paper:
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
* 
* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus q/qi. The qi is generally the largest. In the code below,
* ModReduce is written for ILVectorArray2n and it drops the last tower while updating the necessary parameters. 
*/
template<class Element> inline
void LPLeveledSHEAlgorithmLTV<Element>::ModReduce(Ciphertext<Element> *cipherText) const {

	throw std::logic_error("fix me in ModReduce of LPLeveledSHEAlgorithmLTV");
//	Element cipherTextElement(cipherText->GetElement());
//
//	BigBinaryInteger plaintextModulus(cipherText->GetCryptoParameters().GetPlaintextModulus());
//
//	cipherTextElement.ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.
//
//	cipherText->SetElement(cipherTextElement);
	
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
void LPLeveledSHEAlgorithmLTV<Element>::RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKeyNTRU<Element>> keySwitchHint) const {

		//KeySwitching to a cipherText that can be decrypted by a sparse key. 
		cipherText = KeySwitch( keySwitchHint, cipherText) ;

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
shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmLTV<Element>::ComposedEvalMult(
		const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<Ciphertext<Element>> cipherText2,
		const shared_ptr<LPEvalKeyNTRU<Element>> quadKeySwitchHint) const {

	if(!(cipherText1->GetCryptoParameters() == cipherText2->GetCryptoParameters()) ) {
		std::string errMsg = "ComposedEvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> cipherTextResult;

	const LPPublicKeyEncryptionSchemeLTV<Element> &scheme = dynamic_cast< const LPPublicKeyEncryptionSchemeLTV<Element> &>( this->GetScheme() );

	cipherTextResult = scheme.EvalMult(cipherText1, cipherText2);

	//*cipherTextResult = scheme.m_algorithmLeveledSHE->KeySwitch(quadKeySwitchHint,*cipherTextResult);
	cipherTextResult = scheme.KeySwitch(quadKeySwitchHint, cipherTextResult);

	//scheme.m_algorithmLeveledSHE->ModReduce(cipherTextResult);
	scheme.ModReduce(cipherTextResult);
	
	return cipherTextResult;
}

template<class Element>
shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmLTV<Element>::LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<LPEvalKeyNTRU<Element>> linearKeySwitchHint) const {

//	if(!(cipherText1.GetCryptoParameters() == cipherTextResult->GetCryptoParameters())){
//		std::string errMsg = "LevelReduce crypto parameters are not the same";
//		throw std::runtime_error(errMsg);
//	}
	
	const LPPublicKeyEncryptionSchemeLTV<Element> &scheme = dynamic_cast< const LPPublicKeyEncryptionSchemeLTV<Element> &>( this->GetScheme() );

	//*cipherTextResult = scheme.m_algorithmLeveledSHE->KeySwitch(linearKeySwitchHint,cipherText1);
	shared_ptr<Ciphertext<Element>> cipherTextResult = scheme.KeySwitch(linearKeySwitchHint,cipherText1);

	scheme.ModReduce(cipherTextResult);

	return cipherTextResult;
}

template<class Element>
LPKeyPair<Element> LPLeveledSHEAlgorithmLTV<Element>::SparseKeyGen(const CryptoContext<Element> cc) const
{
	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersLTV<Element>>(cc.GetCryptoParameters() );

	const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
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

	kp.secretKey->SetPrivateElement(f);

	Element g(dgg, elementParams, Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	kp.publicKey->SetPublicElementAtIndex(0, std::move(cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse()));

	return kp;
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
shared_ptr<Ciphertext<Element>> LPAlgorithmLTV<Element>::Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
		Element &plaintext) const
{
	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
			std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(publicKey->GetCryptoParameters());

	shared_ptr<Ciphertext<Element>> ciphertext( new Ciphertext<Element>( publicKey->GetCryptoContext() ) );

	const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	const Element &h = publicKey->GetPublicElements().at(0);

	Element s(dgg,elementParams);

	Element e(dgg,elementParams);

	Element c(elementParams);

	plaintext.SwitchFormat();

	c = h*s + p*e + plaintext;

	ciphertext->SetElement(c);

	return ciphertext;
}

template <class Element>
DecryptResult LPAlgorithmLTV<Element>::Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Element *plaintext) const
		{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	Element c( ciphertext->GetElement() );

	Element f = privateKey->GetPrivateElement(); //add const

	Element b = f*c;

	b.SwitchFormat();
	
	*plaintext = b.SignedMod(p);

	return DecryptResult(plaintext->GetLength());
}

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
