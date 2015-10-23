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

#include "lwecrypt.h"
#include <cstring>
#include <iostream>
//#include "saveparams.h"
using namespace std;

namespace lbcrypto {

template <class Element>
bool LPAlgorithmLWENTRU<Element>::KeyGen(LPPublicKey<Element> &publicKey, 
		LPPrivateKey<Element> &privateKey, 
		DiscreteGaussianGenerator &dgg) const
{
	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetAbstractCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;
	
	//cout<<"f="<<f.GetValues()<<endl;


	//added for saving the cryptoparams
	const LPCryptoParametersLWE<Element> &cryptoParamsLWE = static_cast<const LPCryptoParametersLWE<Element>&>(cryptoParams);

	float DistributionParameter = cryptoParamsLWE.GetDistributionParameter();
	float AssuranceMeasure = cryptoParamsLWE.GetAssuranceMeasure();
	float SecurityLevel = cryptoParamsLWE.GetSecurityLevel();
	usint RelinWindow = cryptoParamsLWE.GetRelinWindow(); 
	int Depth = cryptoParamsLWE.GetDepth(); 
	//std::cout<<p<<DistributionParameter<<AssuranceMeasure<<SecurityLevel<<RelinWindow<<Depth<<std::endl;
	//////
	f.SwitchFormat();

	privateKey.SetPrivateElement(f);
	privateKey.AccessAbstractCryptoParameters() = cryptoParams;

	Element g(dgg,elementParams,Format::COEFFICIENT);
	g.SwitchFormat();

	privateKey.SetPrivateErrorElement(g);

	//public key is generated
	privateKey.MakePublicKey(publicKey);

	return true;
}

template <class Element>
void LPAlgorithmLWENTRU<Element>::Encrypt(const LPPublicKey<Element> &publicKey, 
				DiscreteGaussianGenerator &dgg, 
				const PlaintextEncodingInterface &plaintext, 
				Element *ciphertext) const
{

	const LPCryptoParameters<Element> &cryptoParams = publicKey.GetAbstractCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element m(elementParams);
	
	m.EncodeElement(static_cast<const ByteArrayPlaintextEncoding&>(plaintext),p);

	//cout<<"m original ="<<m.GetValues()<<endl;

	m.SwitchFormat();

	const Element &h = publicKey.GetPublicElement();

	Element s(dgg,elementParams);
	Element e(dgg,elementParams);

	//Element a(p*e + m);
	//a.SwitchFormat();

	Element c(elementParams);

	c = h*s + p*e + m;

	*ciphertext = c;

}

template <class Element>
DecodingResult LPAlgorithmLWENTRU<Element>::Decrypt(const LPPrivateKey<Element> &privateKey, 
				const Element &ciphertext, 
				PlaintextEncodingInterface *plaintext) const
{
	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetAbstractCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element c(elementParams);
	c = ciphertext;

	Element b(elementParams);
	Element f = privateKey.GetPrivateElement(); //add const

	b = f*c;

	b.SwitchFormat();

	//Element m(elementParams);
	//m = b.Mod(p);

	//need to be written cleaner - as an Element
	BigBinaryVector mTemp(b.ModByTwo());
	Element m(elementParams);
	m.SetValues(mTemp,Format::COEFFICIENT);

	//cout<<"m ="<<m.GetValues()<<endl;

	m.DecodeElement(static_cast<ByteArrayPlaintextEncoding*>(plaintext),p);

	return DecodingResult(plaintext->GetLength());
}


}  // namespace lbcrypto ends
