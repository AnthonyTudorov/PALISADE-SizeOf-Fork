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
	This code provides the core additive homomorphic encryption functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "lweautomorph.h"

namespace lbcrypto {
			
//Function for extracting a value at a certain index using automorphism operation.
template <class Element>
void LPAlgorithmAutoMorphLTV<Element>::EvalAtIndex(const Ciphertext<Element> &ciphertext, const usint i, 
				const std::vector<LPEvalKey<Element> *> &evalKeys, Ciphertext<Element> *newCiphertext) const

{
	
	usint autoIndex = 2*i - 1;
	usint m = ciphertext.GetElement().GetParams().GetCyclotomicOrder();

	//usint iInverse = ModInverse(autoIndex,m);

	Ciphertext<Element> permutedCiphertext;
	permutedCiphertext = ciphertext;
	//permutedCiphertext.SetElement(ciphertext.GetElement().AutomorphismTransform(iInverse));
	permutedCiphertext.SetElement(ciphertext.GetElement().AutomorphismTransform(autoIndex));

	*newCiphertext = ciphertext;

	this->GetScheme().ReEncrypt(*evalKeys[i-2], permutedCiphertext, newCiphertext);


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
bool LPAlgorithmAutoMorphLTV<Element>::EvalAutomorphismKeyGen(const LPPublicKey<Element> &publicKey, 
	const LPPrivateKey<Element> &origPrivateKey,
	DiscreteGaussianGenerator &ddg, const usint size, LPPrivateKey<Element> *tempPrivateKey, 
	std::vector<LPEvalKey<Element>*> *evalKeys) const
{
	const Element &privateKeyElement = origPrivateKey.GetPrivateElement();
	usint m = privateKeyElement.GetParams().GetCyclotomicOrder();

	if (size > m/2 - 1)
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
			
			tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

			//const LPPublicKeyEncryptionScheme<Element> *scheme = ciphertext.GetEncryptionAlgorithm();

			this->GetScheme().EvalKeyGen(publicKey, *tempPrivateKey, ddg, evalKeys->at(index));

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

// namespace lbcrypto ends
}