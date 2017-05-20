//LAYER 3 : CRYPTO DATA STRUCTURES AND OPERATIONS
/*
 * @file ltv.cpp -- Operations for the LTV cryptoscheme.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This code provides support for the LTV cryptoscheme.
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our design is informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
 *
 * Note that weaknesses have been discovered in this scheme and it should be used carefully.  Weaknesses come from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
*/

#ifndef LBCRYPTO_CRYPTO_LTV_C
#define LBCRYPTO_CRYPTO_LTV_C

#include "ltv.h"

namespace lbcrypto {

template <class Element>
void LPCryptoParametersLTV<Element>::ParameterSelection(LPCryptoParametersLTV<ILVectorArray2n> *cryptoParams)
{

	//defining moduli outside of recursive call for efficiency
	std::vector<native64::BigBinaryInteger> moduli(this->m_depth + 1);
	moduli.reserve(this->m_depth + 1);

	usint n = this->GetElementParams()->GetRingDimension();
	// set the values for n (ring dimension) and chain of moduli
	this->ParameterSelection(n, moduli);

	cryptoParams->SetAssuranceMeasure(this->m_assuranceMeasure);
	cryptoParams->SetDepth(this->m_depth);
	cryptoParams->SetSecurityLevel(this->m_securityLevel);
	cryptoParams->SetDistributionParameter(this->m_distributionParameter);
	cryptoParams->SetPlaintextModulus(this->GetPlaintextModulus());

	std::vector<native64::BigBinaryInteger> rootsOfUnity;
	rootsOfUnity.reserve(this->m_depth + 1);
	usint m = this->GetElementParams()->GetCyclotomicOrder();
	native64::BigBinaryInteger rootOfUnity;

	for (usint i = 0; i < this->m_depth + 1; i++) {
		rootOfUnity = RootOfUnity(m, moduli.at(i));
		rootsOfUnity.push_back(rootOfUnity);
	}

	shared_ptr<typename ILVectorArray2n::Params> newElemParams(new typename ILVectorArray2n::Params(m, moduli, rootsOfUnity));
	cryptoParams->SetElementParams(newElemParams);

}

template <class Element>
void LPCryptoParametersLTV<Element>::ParameterSelection(usint& n, vector<native64::BigBinaryInteger> &moduli) {
	int t = this->m_depth + 1;
	int d = this->m_depth;

	native64::BigBinaryInteger pBigBinaryInteger(this->GetPlaintextModulus().ConvertToInt());
	int p = pBigBinaryInteger.ConvertToInt(); // what if this does not fit in an int? (unlikely)
	double w = this->m_assuranceMeasure;
	double r = this->m_distributionParameter;
	double rootHermitFactor = this->m_securityLevel;

	double sqrtn = sqrt(n);
	double q1 = 4 * p * r * sqrtn * w;
	double q2 = 4 * pow(p, 2) * pow(r, 5) * pow(sqrtn, 3) * pow(w, 5); // maybe p * p instead

	double* q = new double[t];
	q[0] = q1;
	for (int i = 1; i<t; i++)
		q[i] = q2;

	double sum = 0.0;
	for (int i = 0; i<t; i++) {
		sum += log(q[i]);  /// probably needs to be log2?????
	}

	// which log are we using???
	int next = ceil(sum / (4 * log(rootHermitFactor)));
	int nprime = pow(2, ceil(log(next) / log(2)));
	char c = '.';

	// splitting a string version on dot is ... probably ... wrong
	if (n == nprime) {
		sum = 0.0;
		for (int i = 0; i<t; i++) {
			if (i == 0 || i == 1) {
				moduli[i] = native64::BigBinaryInteger(split(std::to_string(q[i]), c));
			}
			else {
				moduli[i] = moduli[i - 1];
			}
			NextQ(moduli[i], pBigBinaryInteger, n, native64::BigBinaryInteger("4"), native64::BigBinaryInteger("4"));
			q[i] = moduli[i].ConvertToDouble();
			sum += log(q[i]);
		}

		int nprimeCalcFactor = ceil(sum / (4 * log(rootHermitFactor)));
		if (nprime < nprimeCalcFactor) {
			n *= 2;
			ParameterSelection(n, moduli);
		}
	}
	else {
		n *= 2;
		ParameterSelection(n, moduli);
	}

	delete q;
}

template <class Element>
LPKeyPair<Element> LPAlgorithmLTV<Element>::KeyGen(const CryptoContext<Element> cc, bool makeSparse) const
{
	LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(cc.GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	Element f(elementParams, Format::COEFFICIENT);
	do {
		f = Element(dgg, elementParams, Format::COEFFICIENT);
		f = p*f;

		f = f + BigBinaryInteger::ONE;

		if( makeSparse )
			f.MakeSparse(2);

		f.SwitchFormat();
	} while (!f.InverseExists());

	kp.secretKey->SetPrivateElement(f);

	Element g(dgg, elementParams, Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	kp.publicKey->SetPublicElementAtIndex(0, std::move(p*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse()));

	return kp;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmLTV<Element>::Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
	ILVector2n &ptxt) const
{
	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(publicKey->GetCryptoParameters());

	shared_ptr<Ciphertext<Element>> ciphertext(new Ciphertext<Element>(publicKey->GetCryptoContext()));

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	const Element &h = publicKey->GetPublicElements().at(0);

	Element s(dgg, elementParams);

	Element e(dgg, elementParams);

	Element c(elementParams);

	Element plaintext(ptxt, elementParams);
	plaintext.SwitchFormat();

	c = h*s + p*e + plaintext;

	ciphertext->SetElement(c);

	return ciphertext;
}

template <class Element>
DecryptResult LPAlgorithmLTV<Element>::Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
	const shared_ptr<Ciphertext<Element>> ciphertext,
	ILVector2n *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const Element& c = ciphertext->GetElement();

	const Element& f = privateKey->GetPrivateElement();

	Element b = f*c;

	b.SwitchFormat();

	// Interpolation is needed in the case of Double-CRT interpolation, for example, ILVectorArray2n
	// CRTInterpolate does nothing when dealing with single-CRT ring elements, such as ILVector2n
	ILVector2n interpolatedElement = b.CRTInterpolate();
	*plaintext = interpolatedElement.SignedMod(p);

	return DecryptResult(plaintext->GetLength());

}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalAdd(
	const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2) const
{
	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "EvalAdd crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	const Element& c1 = ciphertext1->GetElement();

	const Element& c2 = ciphertext2->GetElement();

	Element cResult = c1 + c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalSub(
	const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2) const
{
	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "EvalSub crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	const Element& c1 = ciphertext1->GetElement();

	const Element& c2 = ciphertext2->GetElement();

	Element cResult = c1 - c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

// Homomorphic multiplication of ciphertexts without key switching
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalMult(
	const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2) const
{

	if (ciphertext1->GetElement().GetFormat() == Format::COEFFICIENT || ciphertext2->GetElement().GetFormat() == Format::COEFFICIENT) {
		throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
	}

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "EvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	const Element& c1 = ciphertext1->GetElement();

	const Element& c2 = ciphertext2->GetElement();

	Element cResult = c1 * c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

// Homomorphic multiplication of ciphertexts with key switching
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const {

	const shared_ptr<LPPublicKeyEncryptionSchemeLTV<Element>> scheme =
			std::dynamic_pointer_cast<LPPublicKeyEncryptionSchemeLTV<Element>>(ciphertext1->GetCryptoContext().GetEncryptionAlgorithm());

	shared_ptr<Ciphertext<Element>> newCiphertext = scheme->EvalMult(ciphertext1, ciphertext2); 

	newCiphertext = scheme->KeySwitch(ek,newCiphertext);

	return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const {

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

	const Element& c1 = ciphertext->GetElement();

	newCiphertext->SetElement(c1.Negate());

	return newCiphertext;
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
shared_ptr<LPEvalKey<Element>> LPAlgorithmSHELTV<Element>::KeySwitchGen(
	const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
	const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {

	shared_ptr<LPEvalKey<Element>> keySwitchHint(new LPEvalKeyNTRU<Element>(originalPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(originalPrivateKey->GetCryptoParameters());

	const Element& f1 = originalPrivateKey->GetPrivateElement();
	const Element& f2 = newPrivateKey->GetPrivateElement();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	Element e(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

	e.SwitchFormat();

	Element m(p*e);

	m.AddILElementOne();

	Element newKeyInverse = f2.MultiplicativeInverse();

	Element keySwitchHintElement(m * f1 * newKeyInverse);

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
* KeySwitch takes in a KeySwitchHint and a cipher text. Based on the two, it calculates and returns a new ciphertext.
* if the KeySwitchHint constructed for Private Key A is converted to Private Key B, then the new ciphertext, originally encrypted with
* private key A, is now decryptable by private key B (and not A).
*/
template<class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::KeySwitch(
	const shared_ptr<LPEvalKey<Element>> keySwitchHint,
	const shared_ptr<Ciphertext<Element>> cipherText) const {

	//Get the EvalKeyNTRU to perform key swich, also verfies if proper EvalKey is instantiated.
	const shared_ptr<LPEvalKeyNTRU<Element>> keyHint = std::dynamic_pointer_cast<LPEvalKeyNTRU<Element>>(keySwitchHint);

	shared_ptr<Ciphertext<Element>> newCipherText(new Ciphertext<Element>(cipherText->GetCryptoContext()));

	Element newCipherTextElement = cipherText->GetElement() * keyHint->GetA();

	newCipherText->SetElement(newCipherTextElement);

	return newCipherText;
}


//Function to generate an evaluation key for homomorphic evaluation (for depth 2)
template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmSHELTV<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const
{

	const Element& f = originalPrivateKey->GetPrivateElement();

	shared_ptr<LPPrivateKey<Element>> quadraticPrivateKey(new LPPrivateKey<Element>(originalPrivateKey->GetCryptoContext()));
	quadraticPrivateKey->SetPrivateElement(std::move(f*f));

	return KeySwitchGen(quadraticPrivateKey,originalPrivateKey);

}

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmSHELTV<Element>::KeySwitchRelinGen(const shared_ptr<LPPublicKey<Element>> newPublicKey,
	const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
{

	// create a new EvalKey of the proper type, in this context
	shared_ptr<LPEvalKeyNTRURelin<Element>> ek(new LPEvalKeyNTRURelin<Element>(newPublicKey->GetCryptoContext()));

	// the wrapper checked to make sure that the input keys were created in the proper context

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(newPublicKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();
	const Element &f = origPrivateKey->GetPrivateElement();

	const Element &hn = newPublicKey->GetPublicElements().at(0);

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<Element> evalKeyElements(f.PowersOfBase(relinWindow));

	const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();

	for (usint i = 0; i < evalKeyElements.size(); ++i)
	{
		Element s(dgg, elementParams, Format::EVALUATION);
		Element e(dgg, elementParams, Format::EVALUATION);

		evalKeyElements.at(i) += hn*s + p*e;
	}

	ek->SetAVector(std::move(evalKeyElements));

	return ek;
}

//Function for re-encypting ciphertext using the array generated by KeySwitchRelinGen
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::KeySwitchRelin(const shared_ptr<LPEvalKey<Element>>evalKey,
	const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(*ciphertext));

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(evalKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();

	const std::vector<Element> &proxy = evalKey->GetAVector();

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	const Element& c = ciphertext->GetElement();

	std::vector<Element> digits(c.BaseDecompose(relinWindow));

	Element ct(digits[0] * proxy[0]);

	for (usint i = 1; i < digits.size(); ++i)
		ct += digits[i] * proxy[i];

	newCiphertext->SetElement(std::move(ct));

	return newCiphertext;
}

 //Function for extracting a value at a certain index using automorphism operation.
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext,
	usint i, const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const

{
	usint autoIndex = 2 * i - 1;

	return this->EvalAutomorphism(ciphertext, autoIndex, evalKeys);
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
	const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const
{

	shared_ptr<Ciphertext<Element>> permutedCiphertext(new Ciphertext<Element>(*ciphertext));

	permutedCiphertext->SetElement(ciphertext->GetElement().AutomorphismTransform(i));

	return ciphertext->GetCryptoContext().GetEncryptionAlgorithm()->KeySwitchRelin(evalKeys[(i - 3) / 2], permutedCiphertext);

}

template <class Element>
shared_ptr<std::vector<shared_ptr<LPEvalKey<Element>>>> LPAlgorithmSHELTV<Element>::EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
	const shared_ptr<LPPrivateKey<Element>> origPrivateKey, usint size) const
{
	const Element &privateKeyElement = origPrivateKey->GetPrivateElement();
	usint m = privateKeyElement.GetCyclotomicOrder();

	shared_ptr<LPPrivateKey<Element>> tempPrivateKey(new LPPrivateKey<Element>(origPrivateKey->GetCryptoContext()));

	shared_ptr<std::vector<shared_ptr<LPEvalKey<Element>>>> evalKeys(new std::vector<shared_ptr<LPEvalKey<Element>>>());

	if (size > m / 2 - 1)
		throw std::logic_error("size exceeds allowed limit: maximum is m/2");
	else {

		usint i = 3;

		for (usint index = 0; index < size; index++)
		{
			Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(i);

			tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

			evalKeys->push_back(publicKey->GetCryptoContext().GetEncryptionAlgorithm()->KeySwitchRelinGen(publicKey, tempPrivateKey));

			i = i + 2;
		}

	}

	return evalKeys;
}

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmPRELTV<Element>::ReKeyGen(const shared_ptr<LPPublicKey<Element>> newPK,
	const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
{
	return origPrivateKey->GetCryptoContext().GetEncryptionAlgorithm()->KeySwitchRelinGen(newPK, origPrivateKey);
}

//Function for re-encypting ciphertext using the array generated by ReKeyGen
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmPRELTV<Element>::ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
	const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	return ciphertext->GetCryptoContext().GetEncryptionAlgorithm()->KeySwitchRelin(evalKey, ciphertext);
}


/**
* This function performs ModReduce on ciphertext element and private key element. The algorithm can be found from this paper:
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
*
* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus q/qi. The qi is generally the largest. In the code below,
* ModReduce is written for ILVectorArray2n and it drops the last tower while updating the necessary parameters.
*/
template<class Element> inline
shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmLTV<Element>::ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const {

	shared_ptr<Ciphertext<Element>> newcipherText(new Ciphertext<Element>(cipherText->GetCryptoContext()));

	Element cipherTextElement(cipherText->GetElement());

	const BigBinaryInteger& plaintextModulus = cipherText->GetCryptoParameters()->GetPlaintextModulus();

	cipherTextElement.ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.

	newcipherText->SetElement(cipherTextElement);

	return newcipherText;

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
shared_ptr<Ciphertext<Element>>
LPLeveledSHEAlgorithmLTV<Element>::RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const {

	//KeySwitching to a cipherText that can be decrypted by a sparse key.
	shared_ptr<Ciphertext<Element>> newcipherText = cipherText->GetCryptoContext().KeySwitch(keySwitchHint, cipherText);

	//Once the keyswitching of the ciphertext has been done, based on the algorithm in the referenced paper, the ciphertext needs to be decomposed.
	Element keySwitchedCipherTextElement(newcipherText->GetElement());

	//changing from EVALUATION to COEFFICIENT domain before performing Decompose operation. Decompose is done in coeffiecient domain.
	keySwitchedCipherTextElement.SwitchFormat();

	/*Based on the algorithm their needs to be a decompose done on the ciphertext. The W factor in this function is 2. The decompose is done
	on the elements of keySwitchedCipherTextElement*/
	keySwitchedCipherTextElement.Decompose();

	//Converting back to EVALUATION representation.
	keySwitchedCipherTextElement.SwitchFormat();

	//setting the decomposed element into ciphertext.
	newcipherText->SetElement(keySwitchedCipherTextElement);

	return newcipherText;
}

template<class Element>
shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmLTV<Element>::ComposedEvalMult(
	const shared_ptr<Ciphertext<Element>> cipherText1,
	const shared_ptr<Ciphertext<Element>> cipherText2,
	const shared_ptr<LPEvalKey<Element>> ek) const {

	shared_ptr<Ciphertext<Element>> prod = cipherText1->GetCryptoContext().GetEncryptionAlgorithm()->EvalMult(cipherText1, cipherText2);

	prod = prod->GetCryptoContext().GetEncryptionAlgorithm()->KeySwitch(ek, prod);

	return this->ModReduce(prod);
}

template<class Element>
shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmLTV<Element>::LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
	const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const {

	shared_ptr<Ciphertext<Element>> cipherTextResult = cipherText1->GetCryptoContext().GetEncryptionAlgorithm()->KeySwitch(linearKeySwitchHint, cipherText1);

	return this->ModReduce(cipherTextResult);
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
	double powerValue = log2(multipliedModuli) / (4 * ringDimension);
	double powerOfTwo = pow(2, powerValue);

	return rootHermiteFactor >= powerOfTwo;
}

// Constructor for LPPublicKeyEncryptionSchemeLTV
template <class Element>
LPPublicKeyEncryptionSchemeLTV<Element>::LPPublicKeyEncryptionSchemeLTV(std::bitset<FEATURESETSIZE> mask)
	: LPPublicKeyEncryptionScheme<Element>() {

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmLTV<Element>();
	if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>();
	if (mask[SHE])
		this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
	if (mask[LEVELEDSHE])
		this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>();

}

// Enable for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeLTV<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmLTV<Element>();
		break;
	case PRE:
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
		break;
	case SHE:
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
		break;
	case LEVELEDSHE:
		if (this->m_algorithmLeveledSHE == NULL)
			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>();
		break;
	}
}




}  // namespace lbcrypto ends

#endif
