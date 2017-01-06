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
http://dx.doi.org/10.1007/978-3-642-22792-9_29). 
The levelled Homomorphic scheme is described in 
"Fully Homomorphic Encryption without Bootstrapping", Internet Source: https://eprint.iacr.org/2011/277.pdf .
Implementation details are provided in
"Homomorphic Evaluation of the AES Circuit" Internet source: https://eprint.iacr.org/2012/099.pdf .

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
	LPKeyPair<Element> LPAlgorithmBV<Element>::KeyGen(const CryptoContext<Element> cc, bool makeSparse) const
	{
		if( makeSparse )
			return LPKeyPair<Element>();

		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBV<Element>>(cc.GetCryptoParameters());

		const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();

		const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

		const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		const DiscreteUniformGenerator dug(elementParams->GetModulus());

		TernaryUniformGenerator tug;

		//Generate the element "a" of the public key
		Element a(dug, elementParams, Format::EVALUATION);
		
		//Generate the secret key
		Element s;

		//Done in two steps not to use a random polynomial from a pre-computed pool
		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		if (cryptoParams->GetMode() == RLWE) {
			s = Element(dgg, elementParams, Format::COEFFICIENT);
		}
		else {
			s = Element(tug, elementParams, Format::COEFFICIENT);
		}
		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();

		Element b = a*s + p*e;

		kp.secretKey->SetPrivateElement(std::move(s));

		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));

		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		return kp;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmBV<Element>::Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
		Element &plaintext) const
	{

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(publicKey->GetCryptoParameters());

		shared_ptr<Ciphertext<Element>> ciphertext(new Ciphertext<Element>(publicKey->GetCryptoContext()));

		const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
		const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();
		const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		TernaryUniformGenerator tug;

		const Element &a = publicKey->GetPublicElements().at(0);
		const Element &b = publicKey->GetPublicElements().at(1);



		//Element v(dgg, elementParams, Format::EVALUATION);
		Element v;

		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		if (cryptoParams->GetMode() == RLWE)
			v = Element(dgg, elementParams, Format::EVALUATION);
		else
			v = Element(tug, elementParams, Format::EVALUATION);

		Element e0(dgg, elementParams, Format::EVALUATION);
		Element e1(dgg, elementParams, Format::EVALUATION);

		plaintext.SwitchFormat();

		Element c0( b*v + p*e0 + plaintext );

		Element c1( a*v + p*e1 );

		std::vector<Element> cVector;

		cVector.push_back(std::move(c0));

		cVector.push_back(std::move(c1));

		ciphertext->SetElements(std::move(cVector));

		return ciphertext;
	}

	template <class Element>
	DecryptResult LPAlgorithmBV<Element>::Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Element *plaintext) const
	{

		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();

		const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

		const std::vector<Element> &c = ciphertext->GetElements();

		const Element &s = privateKey->GetPrivateElement();

		Element b = c[0] - s*c[1];

		b.SwitchFormat();

		*plaintext = b.SignedMod(p);

		return DecryptResult(plaintext->GetLength());

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalAdd(
		const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
	{
		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] + c2[0]));

		cNew.push_back(std::move(c1[1] + c2[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}

	//TODO: CHECK IMPLEMENTATION
	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const {

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] - c2[0]));

		cNew.push_back(std::move(c1[1] - c2[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalMult(
		const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
	{

		if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
			throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
		}

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] * c2[0]));

		cNew.push_back(std::move(c1[0] * c2[1] + c1[1] * c2[0]));

		cNew.push_back(std::move(c1[1] * c2[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}


	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const {

		if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
			throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
		}

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(ek->GetCryptoParameters());

		usint relinWindow = cryptoParamsLWE->GetRelinWindow();

		const shared_ptr<LPEvalKeyRelin<Element>> ekRelin = std::dynamic_pointer_cast<LPEvalKeyRelin<Element>>(ek);

		shared_ptr<Ciphertext<Element>> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

		const Element &c0 = newCiphertext->GetElements().at(0);

		const Element &c1 = newCiphertext->GetElements().at(1);

		const Element &c2 = newCiphertext->GetElements().at(2);

		std::vector<Element> finalElements;

		finalElements.push_back(std::move(c0));

		finalElements.push_back(std::move(c1));

		const std::vector<Element> &b = ekRelin->GetBVector();

		const std::vector<Element> &a = ekRelin->GetAVector();

		std::vector<Element> c2Decomposed(c2.BaseDecompose(relinWindow));

		for (usint i = 0; i < c2Decomposed.size(); i++) {
			finalElements.at(0) += c2Decomposed.at(i)*b.at(i);

			finalElements.at(1) += c2Decomposed.at(i)*a.at(i);
		}

		newCiphertext->SetElements(std::move(finalElements));

		return newCiphertext;

	}
	

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const {

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

		const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

		Element c0 = cipherTextElements[0].Negate();
		Element c1 = cipherTextElements[1].Negate();

		newCiphertext->SetElements({ c0, c1 });
		return newCiphertext;
	}

	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmSHEBV<Element>::KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey, const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(originalPrivateKey->GetCryptoParameters());

		const shared_ptr<ElemParams> originalKeyParams = cryptoParams->GetElementParams();

		const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

		shared_ptr<LPEvalKey<Element>> keySwitchHintRelin(new LPEvalKeyRelin<Element>(originalPrivateKey->GetCryptoContext()));

		const Element &sNew = newPrivateKey->GetPrivateElement();

		const Element &s = originalPrivateKey->GetPrivateElement();

		const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		const DiscreteUniformGenerator dug(originalKeyParams->GetModulus());

		usint relinWindow = cryptoParams->GetRelinWindow();

		std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

		std::vector<Element> evalKeyElementsGenerated;

		for (usint i = 0; i < (evalKeyElements.size()); i++)
		{
			// Generate a_i vectors
			Element a(dug, originalKeyParams, Format::EVALUATION);

			evalKeyElementsGenerated.push_back(a); //alpha's of i

			// Generate a_i * newSK + p * e - PowerOfBase(oldSK)
			Element e(dgg, originalKeyParams, Format::EVALUATION);

			evalKeyElements.at(i) = (a*sNew + p*e) - evalKeyElements.at(i);

		}

		keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

		keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

		return keySwitchHintRelin;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::KeySwitch(const shared_ptr<LPEvalKey<Element>> keySwitchHint, const shared_ptr<Ciphertext<Element>> cipherText) const {

		shared_ptr<Ciphertext<Element>> x;

		return x;

	}

	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmSHEBV<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const
	{
		shared_ptr<LPEvalKeyRelin<Element>> quadraticKeySwitchHint(new LPEvalKeyRelin<Element>(originalPrivateKey->GetCryptoContext()));

		shared_ptr<LPPrivateKey<Element>> originalPrivateKeySquared = std::shared_ptr<LPPrivateKey<Element>>(new LPPrivateKey<Element>(originalPrivateKey->GetCryptoContext()));

		Element sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

		sSquare = sSquare.Negate();

		originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

		return this->KeySwitchGen(originalPrivateKeySquared , originalPrivateKey);

	}

	

	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmPREBV<Element>::ReKeyGen(const shared_ptr<LPKey<Element>> newSK,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
	{
		// create a new ReKey of the proper type, in this context
		shared_ptr<LPEvalKeyRelin<Element>> EK(new LPEvalKeyRelin<Element>(newSK->GetCryptoContext()));

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(newSK->GetCryptoParameters());

		if (cryptoParamsLWE == 0) {
			throw std::logic_error("Secret Key crypto parameters have incorrect type in LPAlgorithmPREBV<Element>::ReKeyGen");
		}

		const shared_ptr<ElemParams> elementParams = cryptoParamsLWE->GetElementParams();
		const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();
		const Element &s = origPrivateKey->GetPrivateElement();

		const shared_ptr<LPPrivateKey<Element>> newPrivateKey =
			std::dynamic_pointer_cast<LPPrivateKey<Element>>(newSK);

		if (newPrivateKey == 0) {
			throw std::logic_error("Secret Key has incorrect type in LPAlgorithmPREBV<Element>::ReKeyGen");
		}

		//LPEvalKeyBV<Element> *evalKey = dynamic_cast<LPEvalKeyBV<Element>*>(EK);

		const Element &sNew = newPrivateKey->GetPrivateElement();

		const DiscreteGaussianGenerator &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
		const DiscreteUniformGenerator dug(elementParams->GetModulus());

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
			evalKeyElements.at(i) *= (elementParams->GetModulus() - BigBinaryInteger::ONE);//change it wrong implementation

		}

		EK->SetAVector(std::move(evalKeyElements));
		EK->SetBVector(std::move(evalKeyElementsGenerated));

		return EK;

	}

	//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmPREBV<Element>::ReEncrypt(const shared_ptr<LPEvalKey<Element>> EK,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
	{
		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(*ciphertext));

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(EK->GetCryptoParameters());

		const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();

		const shared_ptr<LPEvalKeyRelin<Element>> evalKey = std::static_pointer_cast<LPEvalKeyRelin<Element>>(EK);

		const std::vector<Element> &a = evalKey->GetAVector();
		const std::vector<Element> &b = evalKey->GetBVector();

		usint relinWindow = cryptoParamsLWE->GetRelinWindow();

		const std::vector<Element> &c = ciphertext->GetElements();

		std::vector<Element> digitsC1(c[1].BaseDecompose(relinWindow));

		
		Element ct0(c[0] + digitsC1[0] * b[0]);
		Element ct1(digitsC1[0] * a[0]);

		for (usint i = 1; i < digitsC1.size(); ++i)
		{
			ct0 += digitsC1[i] * b[i];
			ct1 += digitsC1[i] * a[i];
		}

		newCiphertext->SetElements({ ct0, ct1 });
		return newCiphertext;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmBV<Element>::ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const {
		
		shared_ptr<Ciphertext<Element>> newcipherText(new Ciphertext<Element>(*cipherText));

		std::vector<Element> cipherTextElements(cipherText->GetElements());

		BigBinaryInteger plaintextModulus(cipherText->GetCryptoParameters()->GetPlaintextModulus());

		for (auto &cipherTextElement : cipherTextElements) {
			cipherTextElement.ModReduce(plaintextModulus);// this is being done at the lattice layer. The ciphertext is mod reduced.
		}


		newcipherText->SetElements(cipherTextElements);

		return newcipherText;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmBV<Element>::RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const {
		return cipherText;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmBV<Element>::ComposedEvalMult(
		const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<Ciphertext<Element>> cipherText2,
		const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const {
		return cipherText1;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmBV<Element>::LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const {
		return cipherText1;
	}

	template <class Element>
	bool LPLeveledSHEAlgorithmBV<Element>::CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const {
		return false;
	}


	// Constructor for LPPublicKeyEncryptionSchemeBV
	template <class Element>
	LPPublicKeyEncryptionSchemeBV<Element>::LPPublicKeyEncryptionSchemeBV(std::bitset<FEATURESETSIZE> mask)
		: LPPublicKeyEncryptionScheme<Element>() {

		if (mask[ENCRYPTION])
			this->m_algorithmEncryption = new LPAlgorithmBV<Element>();

		if (mask[PRE])
			this->m_algorithmPRE = new LPAlgorithmPREBV<Element>();

		if (mask[SHE])
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();

		/*		if (mask[FHE])
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(); */
		if (mask[LEVELEDSHE])
			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>();
	}

	// Enable for LPPublicKeyEncryptionSchemeLTV
	template <class Element>
	void LPPublicKeyEncryptionSchemeBV<Element>::Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmBV<Element>();
			break;
		case PRE:
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE = new LPAlgorithmPREBV<Element>();
			break;
		case SHE:
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHEBV<Element>();
			break;
		case LEVELEDSHE:
			if (this->m_algorithmLeveledSHE == NULL)
				this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmBV<Element>();
			break;
			/*
			case FHE:
			if (this->m_algorithmFHE == NULL)
			this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>();
			break;
			*/
		}
	}

}  // namespace lbcrypto ends

#endif
