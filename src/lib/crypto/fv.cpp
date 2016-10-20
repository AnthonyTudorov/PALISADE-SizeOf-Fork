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

 This code implements the Fan-Vercauteren (FV) homomorphic encryption scheme.
 The FV scheme is introduced in https://eprint.iacr.org/2012/144.pdf and originally implemented in https://eprint.iacr.org/2014/062.pdf 
 (this paper has optimized correctness constraints, which are used here as well). 

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef LBCRYPTO_CRYPTO_FV_C
#define LBCRYPTO_CRYPTO_FV_C

#include "../crypto/cryptocontext.h"
#include <iostream>
#include <fstream>

namespace lbcrypto {

template <class Element>
bool LPAlgorithmParamsGenFV<Element>::ParamsGen(LPCryptoParameters<Element> *cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{

	if (cryptoParams == 0)
		return false;

	LPCryptoParametersFV<Element> *cryptoParamsFV =
		dynamic_cast<LPCryptoParametersFV<Element>*>(cryptoParams);

	float sigma = cryptoParamsFV->GetDistributionParameter();
	float alpha = cryptoParamsFV->GetAssuranceMeasure();
	float hermiteFactor = cryptoParamsFV->GetSecurityLevel();
	double p = cryptoParamsFV->GetPlaintextModulus().ConvertToDouble();
	uint32_t r = cryptoParamsFV->GetRelinWindow();

	//Bound of the Gaussian error polynomial
	double Berr = sigma*sqrt(alpha);

	//Bound of the key polynomial
	double Bkey = sigma*sqrt(alpha);

	//expansion factor delta
	auto delta = [](uint32_t n) -> double { return sqrt(n); };

	//norm of fresh ciphertext polynomial
	auto Vnorm = [&](uint32_t n) -> double { return Berr*(1+2*delta(n)*Bkey);  };

	//RLWE security constraint
	auto nRLWE = [&](double q) -> double { return log2(q / sigma) / (4 * log2(hermiteFactor));  };

	//initial values
	uint32_t n = 512;
	double q = 0;
	
	//only public key encryption and EvalAdd (optional when evalAddCount = 0) operations are supported
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	if ((evalMultCount == 0) && (keySwitchCount == 0)) {

		//Correctness constraint
		auto qFV = [&](uint32_t n) -> double { return p*(2*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

		//initial value
		q = qFV(n);

		while (nRLWE(q) > n) {
			n = 2 * n;
			q = qFV(n);
		}

	} 
	//Only EvalMult operations are used in the correctness constraint
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	else if ((evalAddCount == 0) && (evalMultCount > 0) && (keySwitchCount == 0))
	{

		//base for relinearization
		double w = pow(2, r);

		//function used in the EvalMult constraint
		auto epsilon1 = [&](uint32_t n) -> double { return 4 / (delta(n)*p*Bkey);  };

		//function used in the EvalMult constraint
		auto C1 = [&](uint32_t n) -> double { return (1 + epsilon1(n))*delta(n)*delta(n)*p*p*Bkey;  };

		//function used in the EvalMult constraint
		auto C2 = [&](uint32_t n, double qPrev) -> double { return delta(n)*delta(n)*p*Bkey*(p*(Bkey + p) + (floor(log2(qPrev) / r) + 1)*w*Berr);  };

		//main correctness constraint
		auto qFV = [&](uint32_t n, double qPrev) -> double { return p*(2 * (pow(C1(n), evalMultCount)*Vnorm(n) + evalMultCount*pow(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q 
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qFV(n, qPrev);
				qPrev = q;
			}

			q = qFV(n, qPrev);

			while (abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qFV(n, qPrev);
			}

		}

	}

	BigBinaryInteger qPrime = FindPrimeModulus(2 * n, ceil(log2(q))+1);
	BigBinaryInteger rootOfUnity = RootOfUnity(2 * n, qPrime);
	BigBinaryInteger qPrime2 = FindPrimeModulus(2 * n, 2.03*(ceil(log2(q)) + 1));
	BigBinaryInteger rootOfUnity2 = RootOfUnity(2 * n, qPrime2);

	cryptoParamsFV->SetBigModulus(qPrime2);
	cryptoParamsFV->SetBigRootOfUnity(rootOfUnity2);

	//YSP a memory leak is created. This should go away with the new design.
	ILParams* ilParams = new ILParams(2*n, qPrime, rootOfUnity);
	cryptoParamsFV->SetElementParams(*ilParams);

	cryptoParamsFV->SetDelta(qPrime.DividedBy(cryptoParamsFV->GetPlaintextModulus()));

	return true;
	
}

template <class Element>
bool LPAlgorithmFV<Element>::KeyGen(LPPublicKey<Element> *publicKey,
	LPPrivateKey<Element> *privateKey) const
{

	if (publicKey == 0 || privateKey == 0)
		return false;

	const LPCryptoParametersFV<Element> *cryptoParams =
		dynamic_cast<const LPCryptoParametersFV<Element>*>(&privateKey->GetCryptoParameters());

	if (cryptoParams == 0)
		return false;

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	const DiscreteUniformGenerator dug(elementParams.GetModulus());

	//Generate the element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	//Generate the secret key
	//Done in two steps not to use a discrete Gaussian polynomial from a pre-computed pool
	Element s(dgg, elementParams, Format::COEFFICIENT);
	s.SwitchFormat();

	privateKey->SetPrivateElement(s);

	//Done in two steps not to use a discrete Gaussian polynomial from a pre-computed pool
	Element e(dgg, elementParams, Format::COEFFICIENT);
	e.SwitchFormat();

	Element b(elementParams, Format::EVALUATION, true);
	b-=e;
	b-=(a*s);

	publicKey->SetPublicElementAtIndex(0, std::move(b));
	publicKey->SetPublicElementAtIndex(1, std::move(a));

	return true;
}

template <class Element>
EncryptResult LPAlgorithmFV<Element>::Encrypt(const LPPublicKey<Element> &pubKey,
	const Element &plaintext,
	Ciphertext<Element> *ciphertext) const
{

	const LPCryptoParametersFV<Element> *cryptoParams =
		dynamic_cast<const LPCryptoParametersFV<Element>*>(&pubKey.GetCryptoParameters());

	const LPPublicKey<Element> *publicKey =
		dynamic_cast<const LPPublicKey<Element>*>(&pubKey);

	if (cryptoParams == 0) return EncryptResult();

	if (ciphertext == 0) return EncryptResult();

	const ElemParams &elementParams = cryptoParams->GetElementParams();
	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	const BigBinaryInteger &delta = cryptoParams->GetDelta();

	const Element &p0 = publicKey->GetPublicElements().at(0);
	const Element &p1 = publicKey->GetPublicElements().at(1);

	Element u(dgg, elementParams, Format::EVALUATION);
	Element e1(dgg, elementParams, Format::EVALUATION);
	Element e2(dgg, elementParams, Format::EVALUATION);

	Element c0(elementParams);
	Element c1(elementParams);

	c0 = p0*u + e1 + delta*plaintext;

	c1 = p1*u + e2;

	ciphertext->SetCryptoParameters(cryptoParams);
	ciphertext->SetEncryptionAlgorithm(this->GetScheme());
	ciphertext->SetElements({ c0,c1 });

	return EncryptResult(0);
}

template <class Element>
DecryptResult LPAlgorithmFV<Element>::Decrypt(const LPPrivateKey<Element> &privateKey,
	const Ciphertext<Element> &ciphertext,
	Element *plaintext) const
{

	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();
	const BigBinaryInteger &q = elementParams.GetModulus();

	const std::vector<Element> &c = ciphertext.GetElements();

	const Element &s = privateKey.GetPrivateElement();

	Element b = c[0] + s*c[1];

	b.SwitchFormat();

	b = b.MultiplyAndRound(p, q);
	
	*plaintext = b;

	return DecryptResult(plaintext->GetLength());
}

template <class Element>
bool LPAlgorithmSHEFV<Element>::EvalMultKeyGen(const LPPrivateKey<Element> &privateKey, LPEvalKey<Element> *ek) const
{
	const LPCryptoParametersFV<Element> &cryptoParamsLWE = static_cast<const LPCryptoParametersFV<Element>&>(privateKey.GetCryptoParameters());
	const ElemParams &elementParams = cryptoParamsLWE.GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE.GetPlaintextModulus();
	const Element &s = privateKey.GetPrivateElement();

	Element sSquared(s*s);

	const DiscreteGaussianGenerator &dgg = cryptoParamsLWE.GetDiscreteGaussianGenerator();
	const DiscreteUniformGenerator dug(elementParams.GetModulus());

	usint relinWindow = cryptoParamsLWE.GetRelinWindow();

	std::vector<Element> evalKeyElements(sSquared.PowersOfBase(relinWindow));
	std::vector<Element> evalKeyElementsGenerated;

	for (usint i = 0; i < (evalKeyElements.size()); i++)
	{
		// Generate a_i vectors
		Element a(dug, elementParams, Format::EVALUATION);
		evalKeyElementsGenerated.push_back(a);

		// Generate a_i * s + e - PowerOfBase(s^2)
		Element e(dgg, elementParams, Format::EVALUATION);
		evalKeyElements.at(i) -= (a*s + e);
		//evalKeyElements.at(i) *= (elementParams.GetModulus() - BigBinaryInteger::ONE);
	}

	ek->SetAVector(std::move(evalKeyElements));
	ek->SetBVector(std::move(evalKeyElementsGenerated));

	return true;
}

template <class Element>
void LPAlgorithmSHEFV<Element>::EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2, const LPEvalKey<Element> &ek,
				Ciphertext<Element> *newCiphertext) const {

	if(ciphertext1.GetElement().GetFormat() == Format::COEFFICIENT || ciphertext2.GetElement().GetFormat() == Format::COEFFICIENT){
		throw std::runtime_error("LPAlgorithmSHEFV::EvalMult cannot multiply in COEFFICIENT domain.");
	}

	if(!(ciphertext1.GetCryptoParameters() == ciphertext2.GetCryptoParameters()) || !(ciphertext1.GetCryptoParameters() == newCiphertext->GetCryptoParameters())){
		std::string errMsg = "LPAlgorithmSHEFV::EvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	const LPCryptoParametersFV<Element> *cryptoParamsLWE = dynamic_cast<const LPCryptoParametersFV<Element>*>(&ek.GetCryptoParameters());
	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	const ElemParams &elementParams = cryptoParamsLWE->GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE->GetPlaintextModulus();
	const BigBinaryInteger &q = elementParams.GetModulus();

	const BigBinaryInteger &bigModulus = cryptoParamsLWE->GetBigModulus();
	const BigBinaryInteger &bigRootOfUnity = cryptoParamsLWE->GetBigRootOfUnity();
	
	const LPEvalKeyRelin<Element> &evalKey =
		dynamic_cast<const LPEvalKeyRelin<Element>&>(ek);

	std::vector<Element> cipherText1Elements = ciphertext1.GetElements();
	std::vector<Element> cipherText2Elements = ciphertext2.GetElements();

	//converts the ciphertext elements to coefficient format so that the modulus switching can be done
	cipherText1Elements[0].SwitchFormat();
	cipherText1Elements[1].SwitchFormat();
	cipherText2Elements[0].SwitchFormat();
	cipherText2Elements[1].SwitchFormat();

	//switches the modulus to a larger value so that polynomial multiplication w/o mod q can be performed
	cipherText1Elements[0].SwitchModulus(bigModulus, bigRootOfUnity);
	cipherText1Elements[1].SwitchModulus(bigModulus, bigRootOfUnity);
	cipherText2Elements[0].SwitchModulus(bigModulus, bigRootOfUnity);
	cipherText2Elements[1].SwitchModulus(bigModulus, bigRootOfUnity);

	//converts the ciphertext elements back to evaluation representation
	cipherText1Elements[0].SwitchFormat();
	cipherText1Elements[1].SwitchFormat();
	cipherText2Elements[0].SwitchFormat();
	cipherText2Elements[1].SwitchFormat();

	Element c0 = cipherText1Elements[0] * cipherText2Elements[0];
	Element c1 = cipherText1Elements[0] * cipherText2Elements[1] + cipherText1Elements[1] * cipherText2Elements[0];
	Element c2 = cipherText1Elements[1] * cipherText2Elements[1];

	//converts to coefficient representation before rounding
	c0.SwitchFormat();
	c1.SwitchFormat();
	c2.SwitchFormat();

	c0 = c0.MultiplyAndRound(p, q);
	c1 = c1.MultiplyAndRound(p, q);
	c2 = c2.MultiplyAndRound(p, q);

	//switch the modulus back to the original value
	c0.SwitchModulus(q, elementParams.GetRootOfUnity());
	c1.SwitchModulus(q, elementParams.GetRootOfUnity());
	c2.SwitchModulus(q, elementParams.GetRootOfUnity());

	c0.SwitchFormat();
	c1.SwitchFormat();
	//c2.SwitchFormat();

	std::vector<Element> digitsC2;
	c2.BaseDecompose(relinWindow, &digitsC2);

	Element ct0(c0), ct1(c1);
	
	const std::vector<Element> &b = evalKey.GetAVector();
	const std::vector<Element> &a = evalKey.GetBVector();

	for (usint i = 0; i < digitsC2.size(); ++i)
	{
		ct0 += digitsC2[i] * b[i];
		ct1 += digitsC2[i] * a[i];
	}

	*newCiphertext = ciphertext1;
	newCiphertext->SetElements({ct0, ct1});

}

template <class Element>
void LPAlgorithmSHEFV<Element>::EvalAdd(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const {

	if(!(ciphertext1.GetCryptoParameters() == ciphertext2.GetCryptoParameters()) || !(ciphertext1.GetCryptoParameters() == newCiphertext->GetCryptoParameters())){
		std::string errMsg = "LPAlgorithmSHEFV::EvalAdd crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	std::vector<Element> cipherText1Elements = ciphertext1.GetElements();
	std::vector<Element> cipherText2Elements = ciphertext2.GetElements();

	Element c0 = cipherText1Elements[0] + cipherText2Elements[0];
	Element c1 = cipherText1Elements[1] + cipherText2Elements[1];

	newCiphertext->SetElements({ c0,c1 });
}

template <class Element>
void LPAlgorithmSHEFV<Element>::EvalSub(const Ciphertext<Element> &ciphertext1,
	const Ciphertext<Element> &ciphertext2,
	Ciphertext<Element> *newCiphertext) const {

	if (!(ciphertext1.GetCryptoParameters() == ciphertext2.GetCryptoParameters()) || !(ciphertext1.GetCryptoParameters() == newCiphertext->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEFV::EvalSub crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	std::vector<Element> cipherText1Elements = ciphertext1.GetElements();
	std::vector<Element> cipherText2Elements = ciphertext2.GetElements();

	Element c0 = cipherText1Elements[0] - cipherText2Elements[0];
	Element c1 = cipherText1Elements[1] - cipherText2Elements[1];

	newCiphertext->SetElements({ c0,c1 });
}

// Constructor for LPPublicKeyEncryptionSchemeFV
template <class Element>
LPPublicKeyEncryptionSchemeFV<Element>::LPPublicKeyEncryptionSchemeFV(std::bitset<FEATURESETSIZE> mask)
	: LPPublicKeyEncryptionScheme<Element>() {

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmFV<Element>(*this);
	if (mask[SHE])
		this->m_algorithmSHE = new LPAlgorithmSHEFV<Element>(*this);

	/*if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPREFV<Element>(*this);
	if (mask[EVALADD])
		this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
	if (mask[EVALAUTOMORPHISM])
		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
	if (mask[FHE])
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);
	if (mask[LEVELEDSHE])
		this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>(*this);
	*/

}

// Enable for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeFV<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmFV<Element>(*this);
		break;
	case SHE:
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEFV<Element>(*this);
		break;
	/*case PRE:
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREFV<Element>(*this);
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
