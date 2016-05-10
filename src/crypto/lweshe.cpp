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
	This code provides the core somewhat homomorphic encryption functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "lweshe.h"

namespace lbcrypto {
	//template<class Element>
	/*LPAlgorithmSHELTV<Element>::LPAlgorithmSHELTV()
	{

	}*/
	//Function for re-encypting ciphertext using the array generated by ProxyGen
template <class Element>
void LPAlgorithmSHELTV<Element>::EvalMult(
				const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2, 
				Ciphertext<Element> *newCiphertext) const
{
	Ciphertext<Element> ctOut(ciphertext1);

//	ctOut.Mult(ciphertext2);

	*newCiphertext = ctOut;

}  


//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
bool LPAlgorithmSHELTV<Element>::KeySwitchHintGen(const LPPrivateKey<Element> &newPrivateKey, 
				LPPrivateKey<Element> &origPrivateKey,
				usint depth,
				LPKeySwitchHint<Element> *keySwitchHint) const
{
	const LPCryptoParametersLTV<Element> &cryptoParams = static_cast<const LPCryptoParametersLTV<Element>&>(origPrivateKey.GetCryptoParameters());
	DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGenerator();
	const ElemParams &elementParams = cryptoParams.GetElementParams();

	Element m(dgg,elementParams,Format::COEFFICIENT);
/*
	privKeyInverse = inverse(newPrivateKey);

	origPrivateKeyExp = exp(origPrivateKey,depth)

	keySwitchHint = m*origPrivateKeyExp*privKeyInverse;
*/
	return true;

}


//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
bool LPAlgorithmSHELTV<Element>::KeySwitchHintGen(const LPPrivateKey<Element> &privateKey,  
				LPKeySwitchHint<Element> *keySwitchHint) const
{
	const LPCryptoParametersLTV<Element> &cryptoParams = static_cast<const LPCryptoParametersLTV<Element>&>(privateKey.GetCryptoParameters());
	DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGenerator();
	const ElemParams &elementParams = cryptoParams.GetElementParams();

	Element m(dgg,elementParams,Format::COEFFICIENT);
	Element modularInverseOfNewPrivateKey = privateKey.MultiplicativeInverse();

	keySwitchHint->SetHintElement((privateKey.Times(privateKey)).Times(modularInverseOfNewPrivateKey));// frogot to add modulu

	//std::cout << *(keySwitchHint).GetValues() << std::endl;

	return true;

}

template <class Element>
void LPAlgorithmSHELTV<Element>::KeySwitch(const LPKeySwitchHint<Element> &keySwitchHint,
				const Ciphertext<Element> &ciphertext, 
				Ciphertext<Element> *newCiphertext) const
{
	Ciphertext<Element> ctOut();

/*
	ctOut = keySwitchHint * ciphertext;
*/

	*newCiphertext = ctOut;
}  

}
