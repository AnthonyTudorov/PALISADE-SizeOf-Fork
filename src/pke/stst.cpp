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

 This code implements the Stehle-Steinfeld Scheme.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef LBCRYPTO_CRYPTO_STST_C
#define LBCRYPTO_CRYPTO_STST_C

#include "stst.h"

namespace lbcrypto {

	template <class Element>
	LPKeyPair<Element> LPEncryptionAlgorithmStehleSteinfeld<Element>::KeyGen(const CryptoContext<Element> cc, bool makeSparse) const
	{
		if( makeSparse )
			return LPKeyPair<Element>();

		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

		const shared_ptr<LPCryptoParametersStehleSteinfeld<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersStehleSteinfeld<Element>>(cc.GetCryptoParameters());

		const shared_ptr<ElemParams> elementParams = cryptoParams->GetElementParams();
		const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

		const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGeneratorStSt();

		Element f(dgg, elementParams, Format::COEFFICIENT);

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

		Element g(dgg, elementParams, Format::COEFFICIENT);

		g.SwitchFormat();

		//public key is generated
		kp.publicKey->SetPublicElementAtIndex(0, cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse());

		return kp;
	}


	// Constructor for LPPublicKeyEncryptionSchemeStehleSteinfeld
	template <class Element>
	LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>::LPPublicKeyEncryptionSchemeStehleSteinfeld(std::bitset<FEATURESETSIZE> mask)
		: LPPublicKeyEncryptionSchemeLTV<Element>() {
		if (mask[ENCRYPTION])
			this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>();
		if (mask[PRE])
			this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>();
		if (mask[SHE])
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
		if (mask[FHE])
			this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>();
		if (mask[LEVELEDSHE])
			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>();
	}

	// Feature enable method for LPPublicKeyEncryptionSchemeStehleSteinfeld
	template <class Element>
	void LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>::Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>();
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
