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

This code implements the LTV Scheme.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef LBCRYPTO_CRYPTO_LTV_C
#define LBCRYPTO_CRYPTO_LTV_C

#include "ltv.h"

namespace lbcrypto {

template <class Element>
void LPCryptoParametersLTV<Element>::ParameterSelection(LPCryptoParametersLTV<ILVectorArray2n> *cryptoParams)
{

	//defining moduli outside of recursive call for efficiency
	std::vector<BigBinaryInteger> moduli(this->m_depth + 1);
	moduli.reserve(this->m_depth + 1);

	usint n = this->GetElementParams()->GetCyclotomicOrder() / 2;
	// set the values for n (ring dimension) and chain of moduli
	this->ParameterSelection(n, moduli);

	cryptoParams->SetAssuranceMeasure(this->m_assuranceMeasure);
	cryptoParams->SetDepth(this->m_depth);
	cryptoParams->SetSecurityLevel(this->m_securityLevel);
	cryptoParams->SetDistributionParameter(this->m_distributionParameter);
	cryptoParams->SetPlaintextModulus(this->GetPlaintextModulus());

	std::vector<BigBinaryInteger> rootsOfUnity;
	rootsOfUnity.reserve(this->m_depth + 1);
	usint m = n * 2; //cyclotomic order
	BigBinaryInteger rootOfUnity;

	for (usint i = 0; i < this->m_depth + 1; i++) {
		rootOfUnity = RootOfUnity(m, moduli.at(i));
		rootsOfUnity.push_back(rootOfUnity);
	}

	shared_ptr<ElemParams> newElemParams(new ILDCRTParams(m, moduli, rootsOfUnity));
	cryptoParams->SetElementParams(newElemParams);

}

template <class Element>
void LPCryptoParametersLTV<Element>::ParameterSelection(usint& n, vector<BigBinaryInteger> &moduli) {
	int t = this->m_depth + 1;
	int d = this->m_depth;

	BigBinaryInteger pBigBinaryInteger(this->GetPlaintextModulus());
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
				moduli[i] = BigBinaryInteger(split(std::to_string(q[i]), c));
			}
			else {
				moduli[i] = moduli[i - 1];
			}
			NextQ(moduli[i], pBigBinaryInteger, n, BigBinaryInteger("4"), BigBinaryInteger("4"));
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
LPKeyPair<Element> LPAlgorithmLTV<Element>::KeyGen(const CryptoContext<Element> cc) const
{
	LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(cc.GetCryptoParameters());

	if (cryptoParams == 0)
		throw std::logic_error("Wrong type for crypto parameters in LPAlgorithmLTV<Element>::KeyGen");

	const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	Element f(dgg, elementParams, Format::COEFFICIENT);

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

	Element g(dgg, elementParams, Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	kp.publicKey->SetPublicElementAtIndex(0, std::move(cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse()));

	return kp;
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

	shared_ptr<Ciphertext<Element>> newcipherText(cipherText);

	Element cipherTextElement(newcipherText->GetElement());

	BigBinaryInteger plaintextModulus(newcipherText->GetCryptoParameters()->GetPlaintextModulus());

	// FIXME: note this will not work for ILVector2n yet so we must have a small hack here.

	ILVectorArray2n *ep = dynamic_cast<ILVectorArray2n *>(&cipherTextElement);
	if (ep == 0) {
		throw std::logic_error("ModReduce is only implemented for ILVectorArray2n");
	}

	ep->ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.

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
	const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const {

	if (!(cipherText1->GetCryptoParameters() == cipherText2->GetCryptoParameters())) {
		std::string errMsg = "ComposedEvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> cipherTextResult;

	const shared_ptr<LPPublicKeyEncryptionSchemeLTV<Element>> scheme =
			std::dynamic_pointer_cast<LPPublicKeyEncryptionSchemeLTV<Element>>(cipherText1->GetCryptoContext().GetEncryptionAlgorithm());

	cipherTextResult = scheme->EvalMult(cipherText1, cipherText2);

	//*cipherTextResult = scheme.m_algorithmLeveledSHE->KeySwitch(quadKeySwitchHint,*cipherTextResult);
	cipherTextResult = scheme->KeySwitch(quadKeySwitchHint, cipherTextResult);

	//scheme.m_algorithmLeveledSHE->ModReduce(cipherTextResult);
	return this->ModReduce(cipherTextResult);
}

template<class Element>
shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmLTV<Element>::LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
	const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const {

	const shared_ptr<LPPublicKeyEncryptionSchemeLTV<Element>> scheme =
			std::dynamic_pointer_cast<LPPublicKeyEncryptionSchemeLTV<Element>>(cipherText1->GetCryptoContext().GetEncryptionAlgorithm());

	shared_ptr<Ciphertext<Element>> cipherTextResult = scheme->KeySwitch(linearKeySwitchHint, cipherText1);

	return this->ModReduce(cipherTextResult);
}

template<class Element>
LPKeyPair<Element> LPLeveledSHEAlgorithmLTV<Element>::SparseKeyGen(const CryptoContext<Element> cc) const
{
	LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(cc.GetCryptoParameters());

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
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(publicKey->GetCryptoParameters());

	shared_ptr<Ciphertext<Element>> ciphertext(new Ciphertext<Element>(publicKey->GetCryptoContext()));

	const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	const Element &h = publicKey->GetPublicElements().at(0);

	Element s(dgg, elementParams);

	Element e(dgg, elementParams);

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
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	Element c(ciphertext->GetElement());

	Element f = privateKey->GetPrivateElement(); //add const

	Element b = f*c;

	b.SwitchFormat();

	// Interpolation is needed in the case of Double-CRT interpolation, for example, ILVectorArray2n
	// CRTInterpolate does nothing when dealing with single-CRT ring elements, such as ILVector2n
	Element interpolatedElement = b.CRTInterpolate();
	*plaintext = interpolatedElement.SignedMod(p);

	return DecryptResult(plaintext->GetLength());

}

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmPRELTV<Element>::ReKeyGen(const shared_ptr<LPKey<Element>> newPK,
	const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
{
	// create a new ReKey of the proper type, in this context
	shared_ptr<LPEvalKeyNTRURelin<Element>> ek(new LPEvalKeyNTRURelin<Element>(newPK->GetCryptoContext()));

	// the wrapper checked to make sure that the input keys were created in the proper context

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(newPK->GetCryptoParameters());

	if (cryptoParamsLWE == 0) {
		throw std::logic_error("Public key is not using RLWE parameters in LPAlgorithmPRELTV<Element>::ReKeyGen");
	}

	const shared_ptr<ElemParams> elementParams = cryptoParamsLWE->GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();
	const Element &f = origPrivateKey->GetPrivateElement();

	const shared_ptr<LPPublicKey<Element>> newPublicKey = std::dynamic_pointer_cast<LPPublicKey<Element>>(newPK);

	if (newPublicKey == 0) {
		throw std::logic_error("Public Key argument is not an LPPublicKey in LPAlgorithmPRELTV<Element>::ReKeyGen");
	}

	const Element &hn = newPublicKey->GetPublicElements().at(0);

	const DiscreteGaussianGenerator &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<Element> evalKeyElements(f.PowersOfBase(relinWindow));

	for (usint i = 0; i < evalKeyElements.size(); ++i)
	{
		Element s(dgg, elementParams, Format::EVALUATION);
		Element e(dgg, elementParams, Format::EVALUATION);

		evalKeyElements.at(i) += hn*s + p*e;
	}

	ek->SetAVector(std::move(evalKeyElements));

	return ek;

	//usint nBits = elementParams.GetModulus().GetLengthForBase(2);

	//usint relinWindow = cryptoParamsLWE.GetRelinWindow();

	//usint nWindows = nBits / relinWindow;
	//if (nBits % relinWindow > 0)
	//	nWindows++;

	//for(usint i = 0; i < nWindows; ++i)
	//{
	//	Element s(dgg,elementParams);
	//	Element e(dgg,elementParams);

	//	BigBinaryInteger pI(BigBinaryInteger::TWO.ModExp(UintToBigBinaryInteger(i*relinWindow),elementParams.GetModulus()));
	//	evalKeyElements->push_back( hn*s + p*e + pI*f );
	//}

}

//Function for re-encypting ciphertext using the array generated by ProxyGen
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmPRELTV<Element>::ReEncrypt(const shared_ptr<LPEvalKey<Element>>evalKey,
	const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(*ciphertext));

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(evalKey->GetCryptoParameters());

	const shared_ptr<ElemParams> elementParams = cryptoParamsLWE->GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();

	const std::vector<Element> &proxy = evalKey->GetAVector();

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	Element c(ciphertext->GetElement());

	std::vector<Element> digits(c.BaseDecompose(relinWindow));

	Element ct(digits[0] * proxy[0]);

	for (usint i = 1; i < digits.size(); ++i)
		ct += digits[i] * proxy[i];

	//Element ctDigit(elementParams);

	////convert ciphertext to coefficient format
	//c.SwitchFormat();

	//int nBits = elementParams.GetModulus().GetLengthForBase(2);
	//usint nWindows = nBits / relinWindow;
	//if (nBits % relinWindow > 0)
	//	nWindows++;

	//ctDigit = c.GetDigitAtIndexForBase(1,1<<relinWindow);
	//ctDigit.SwitchFormat();

	//Element ct(ctDigit*proxy[0]);

	//for(usint i = 1; i < nWindows; ++i)
	//{
	//	ctDigit = c.GetDigitAtIndexForBase(i*relinWindow + 1, 1<<relinWindow);
	//	ctDigit.SwitchFormat();
	//	ct += ctDigit*proxy[i];
	//}

	newCiphertext->SetElement(ct);

	return newCiphertext;
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

	Element c1(ciphertext1->GetElement());

	Element c2(ciphertext2->GetElement());

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

	Element c1(ciphertext1->GetElement());

	Element c2(ciphertext2->GetElement());

	Element cResult = c1 - c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

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

	Element c1(ciphertext1->GetElement());

	Element c2(ciphertext2->GetElement());

	Element cResult = c1*c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const {

	shared_ptr<Ciphertext<Element>> newCiphertext = this->GetScheme().EvalMult(ciphertext1, ciphertext2); 

	newCiphertext = this->GetScheme().KeySwitch(ek,newCiphertext);

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

	const Element f1 = originalPrivateKey->GetPrivateElement(); //add const
	const Element f2 = newPrivateKey->GetPrivateElement(); //add const
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	Element e(cryptoParams->GetDiscreteGaussianGenerator(), cryptoParams->GetElementParams(), Format::COEFFICIENT);

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


//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmSHELTV<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const
{
	shared_ptr<LPEvalKeyNTRU<Element>> quadraticKeySwitchHint(new LPEvalKeyNTRU<Element>(originalPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(originalPrivateKey->GetCryptoParameters());

	const Element f1 = originalPrivateKey->GetPrivateElement(); //add const

	const Element f1Squared(f1*f1); //squaring the key
	const Element f2 = originalPrivateKey->GetPrivateElement(); //add const
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	Element e(cryptoParams->GetDiscreteGaussianGenerator(), cryptoParams->GetElementParams(), Format::COEFFICIENT);

	e.SwitchFormat();

	Element m(p*e);

	m = p * e;

	m.AddILElementOne();

	Element newKeyInverse = f2.MultiplicativeInverse();

	Element keySwitchHintElement(m * f1Squared * newKeyInverse);

	quadraticKeySwitchHint->SetA(keySwitchHintElement);

	return quadraticKeySwitchHint;
}

   //Function for extracting a value at a certain index using automorphism operation.
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHELTV<Element>::EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext,
	const usint i, const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const

{
	usint autoIndex = 2 * i - 1;
	//usint m = ciphertext.GetElement().GetCyclotomicOrder();

	//usint iInverse = ModInverse(autoIndex,m);

	shared_ptr<Ciphertext<Element>> permutedCiphertext(new Ciphertext<Element>(*ciphertext));

	//permutedCiphertext.SetElement(ciphertext.GetElement().AutomorphismTransform(iInverse));
	permutedCiphertext->SetElement(ciphertext->GetElement().AutomorphismTransform(autoIndex));

	return ciphertext->GetCryptoContext().GetEncryptionAlgorithm()->ReEncrypt(evalKeys[i - 2], permutedCiphertext);


	////debugging

	//Element orig = ciphertext.GetElement();

	//orig.SwitchFormat();

	//std::cout << "original cipher" << orig.GetValues() << std::endl;

	//Element newEl = permutedCiphertext.GetElement();

	//newEl.SwitchFormat();

	//std::cout << "permuted cipher" << "index " << autoIndex << "\n" << newEl.GetValues() << std::endl;

	////end of debugging
}

template <class Element>
bool LPAlgorithmSHELTV<Element>::EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
	const shared_ptr<LPPrivateKey<Element>> origPrivateKey,
	const usint size, shared_ptr<LPPrivateKey<Element>> *tempPrivateKey,
	std::vector<shared_ptr<LPEvalKey<Element>>> *evalKeys) const
{
	const Element &privateKeyElement = origPrivateKey->GetPrivateElement();
	usint m = privateKeyElement.GetCyclotomicOrder();

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(publicKey->GetCryptoParameters());
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	if (size > m / 2 - 1)
		throw std::logic_error("size exceeds the ring dimensions\n");
	else {

		usint i = 3;

		for (usint index = 0; index < size - 1; index++)
		{
			//usint iInverse = ModInverse(i,m);

			//std::cout<< "before " << i << " \n" << privateKeyElement.GetValues() << std::endl;

			//Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(iInverse);

			Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(i);

			//std::cout<< "after " << i << " \n" << permutedPrivateKeyElement.GetValues() << std::endl;

			(*tempPrivateKey)->SetPrivateElement(permutedPrivateKeyElement);

			evalKeys->at(index) = publicKey->GetCryptoContext().GetEncryptionAlgorithm()->ReKeyGen(publicKey, *tempPrivateKey);

			i = i + 2;

			////debugging

			//Element orig = origPrivateKey.GetPrivateElement();

			//orig.SwitchFormat();

			//std::cout << "original key" << "index " << i<< "\n" << orig.GetValues() << std::endl;

			//Element newEl = tempPrivateKey->GetPrivateElement();

			//newEl.SwitchFormat();

			//std::cout << "permuted key" << "index " << i << "\n" << newEl.GetValues() << std::endl;

			////end of debugging

		}

	}
}





//Function for re-encypting ciphertext using the array generated by ProxyGen
template <class Element>
void LPAlgorithmFHELTV<Element>::Bootstrap(const Ciphertext<Element> &ciphertext,
	Ciphertext<Element> *newCiphertext)  const

{
	Ciphertext<Element> ct();

	//*newCiphertext = ct;
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
	if (mask[FHE])
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>();
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
		break;
	case SHE:
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
		break;
	case FHE:
		if (this->m_algorithmFHE == NULL)
			this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>();
		break;
	case LEVELEDSHE:
		if (this->m_algorithmLeveledSHE == NULL)
			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>();
		break;
	}
}




}  // namespace lbcrypto ends

#endif
