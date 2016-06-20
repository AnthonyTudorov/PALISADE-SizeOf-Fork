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

#include "lwepre.h"

namespace lbcrypto {

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
bool LPAlgorithmPRELTV<Element>::EvalKeyGen(const LPPublicKey<Element> &newPublicKey, 
				const LPPrivateKey<Element> &origPrivateKey,
				LPEvalKey<Element> *evalKey) const
{
	const LPCryptoParametersLTV<Element> &cryptoParamsLWE = static_cast<const LPCryptoParametersLTV<Element>&>(newPublicKey.GetCryptoParameters());
	const ElemParams &elementParams = cryptoParamsLWE.GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE.GetPlaintextModulus();
	const Element &f = origPrivateKey.GetPrivateElement();
	const Element &hn = newPublicKey.GetPublicElement();

	const DiscreteGaussianGenerator &dgg = cryptoParamsLWE.GetDiscreteGaussianGenerator();

	std::vector<Element> *evalKeyElements = &evalKey->AccessEvalKeyElements();

	usint nBits = elementParams.GetModulus().GetLengthForBase(2);

	usint relinWindow = cryptoParamsLWE.GetRelinWindow();

	usint nWindows = nBits / relinWindow;
	if (nBits % relinWindow > 0)
		nWindows++;

	for(usint i = 0; i < nWindows; ++i)
	{
		Element s(dgg,elementParams);
		Element e(dgg,elementParams);

		BigBinaryInteger pI(BigBinaryInteger::TWO.ModExp(UintToBigBinaryInteger(i*relinWindow),elementParams.GetModulus()));
		evalKeyElements->push_back( hn*s + p*e + pI*f );
	}

	return true;
}
			
//Function for re-encypting ciphertext using the array generated by ProxyGen
template <class Element>
void LPAlgorithmPRELTV<Element>::ReEncrypt(const LPEvalKey<Element> &evalKey,
	const Ciphertext<Element> &ciphertext,
	Ciphertext<Element> *newCiphertext) const
{
	const LPCryptoParametersLTV<Element> &cryptoParamsLWE = static_cast<const LPCryptoParametersLTV<Element>&>(evalKey.GetCryptoParameters());
	
	const ElemParams &elementParams = cryptoParamsLWE.GetElementParams();
	const BigBinaryInteger &p = cryptoParamsLWE.GetPlaintextModulus();

	const std::vector<Element> &proxy = evalKey.GetEvalKeyElements();

	usint relinWindow = cryptoParamsLWE.GetRelinWindow();

	Element c(ciphertext.GetElement());
	Element ctDigit(elementParams);

	//convert ciphertext to coefficient format
	c.SwitchFormat();

	int nBits = elementParams.GetModulus().GetLengthForBase(2);
	usint nWindows = nBits / relinWindow;
	if (nBits % relinWindow > 0)
		nWindows++;

	ctDigit = c.GetDigitAtIndexForBase(1,1<<relinWindow);
	ctDigit.SwitchFormat();

	Element ct(ctDigit*proxy[0]);

	for(usint i = 1; i < nWindows; ++i)
	{
		ctDigit = c.GetDigitAtIndexForBase(i*relinWindow + 1, 1<<relinWindow);
		ctDigit.SwitchFormat();
		ct += ctDigit*proxy[i];
	}

	*newCiphertext = ciphertext;
	newCiphertext->SetElement(ct);
	newCiphertext->SetPublicKey(evalKey.GetPublicKey());

}

}  // namespace lbcrypto ends