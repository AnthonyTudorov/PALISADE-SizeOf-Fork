
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

#include "sheoperations.h"

namespace lbcrypto {

	template <class Element>	
	Ciphertext<Element> SHEOperations<Element>::KeySwitch(const LPPrivateKeyLTV<Element> &newPrivateKey, 
			LPPrivateKeyLTV<Element> &origPrivateKey,
			DiscreteGaussianGenerator &dgg, 
			Ciphertext<Element> &origCipherText) const {

		Element keySwitchHint(KeySwitchHintGen(newPrivateKey, origPrivateKey, dgg));

		const LPCryptoParameters<Element> &cryptoParamsOriginal = origPrivateKey.GetCryptoParameters();

		const ElemParams &originalKeyParams = cryptoParamsOriginal.GetElementParams();

		Element ciphertextElement(originalKeyParams);

		ciphertextElement = origCipherText.GetElement();

		ciphertextElement = keySwitchHint * ciphertextElement;

		Ciphertext<Element> newCipherText(origCipherText);
		
		newCipherText.SetElement(ciphertextElement);
		
		return newCipherText;
	}

	template <class Element>
	Element SHEOperations<Element>::KeySwitchHintGen(const LPPrivateKeyLTV<Element> &newPrivateKey, 
			LPPrivateKeyLTV<Element> &origPrivateKey,
			DiscreteGaussianGenerator &dgg) const {
	
		const LPCryptoParameters<Element> &cryptoParamsOriginal = origPrivateKey.GetCryptoParameters();
		const ElemParams &originalKeyParams = cryptoParamsOriginal.GetElementParams();

		Element f1 = origPrivateKey.GetPrivateElement(); //add const
		Element f2 = newPrivateKey.GetPrivateElement(); //add const
		const BigBinaryInteger &p = cryptoParamsOriginal.GetPlaintextModulus();

		Element e(dgg,originalKeyParams,Format::COEFFICIENT);
		e.SwitchFormat();

		Element m(originalKeyParams);
		m = p * e;
		
		m.ModularOne();

		Element newKeyInverse = f2.MultiplicativeInverse(); 

		Element keySwitchHint(originalKeyParams);
		keySwitchHint = m * f1 * newKeyInverse;
		return keySwitchHint;

	}

	template <class Element>
	CipherTextSparseKey<Element> SHEOperations<Element>::RingReduce(Ciphertext<Element> &origCipherText, 
		LPPrivateKeyLTV<Element> &origPrivateKey, 
		DiscreteGaussianGenerator &dgg) const {
		
		LPAlgorithmLTV<Element> algorithm;

		LPCryptoParametersLTV<Element> &lpCryptoParams = static_cast<LPCryptoParametersLTV<Element>&>(origPrivateKey.AccessCryptoParameters());

		LPPublicKeyLTV<Element> pk(lpCryptoParams);

		LPPrivateKeyLTV<Element> sparsePrivateKey(lpCryptoParams);
		//change sparsekeygen to not have pk
		algorithm.SparseKeyGen(pk, sparsePrivateKey, dgg);

		Ciphertext<Element> keySwitchedCipherText(this->KeySwitch(sparsePrivateKey, origPrivateKey, dgg, origCipherText));

		ByteArrayPlaintextEncoding ctxtd;
		algorithm.Decrypt(sparsePrivateKey, keySwitchedCipherText, &ctxtd);
		std::cout << "Decryption after key switch: " << std::endl;
		std::cout << ctxtd << std::endl;

		Element keySwitchedCipherTextElement = keySwitchedCipherText.GetElement();
		//changing from EVALUATION to COEFFICIENT domain before performing Decompose operation.
		keySwitchedCipherTextElement.SwitchFormat();

		Element sparsePrivateKeyElement = sparsePrivateKey.GetPrivateElement(); //EVALUATION
		sparsePrivateKeyElement.SwitchFormat(); //COEFF

		LPCryptoParametersLTV<Element> lpCryptoParamsDecomposed;
		lpCryptoParamsDecomposed.SetPlaintextModulus(lpCryptoParams.GetPlaintextModulus());
		lpCryptoParamsDecomposed.SetDistributionParameter(lpCryptoParams.GetDistributionParameter());
		lpCryptoParamsDecomposed.SetRelinWindow(lpCryptoParams.GetRelinWindow());

		usint decomposedCyclotomicOrder = keySwitchedCipherTextElement.GetParams().GetCyclotomicOrder()/2;
		BigBinaryInteger modulus(keySwitchedCipherTextElement.GetParams().GetModulus());
		BigBinaryInteger rootOfUnity(RootOfUnity(decomposedCyclotomicOrder, modulus));
		ElemParams  *decomposedParams = NULL; 

		if(typeid(sparsePrivateKeyElement)==typeid(ILVector2n)){
			ILParams decomposedParamsSRT(decomposedCyclotomicOrder, modulus, rootOfUnity);
			decomposedParams = &decomposedParamsSRT;
		}
		else{
			const ILDCRTParams &ildcrtParams = dynamic_cast<const ILDCRTParams&>(keySwitchedCipherTextElement.GetParams());
			std::vector<BigBinaryInteger> moduli = ildcrtParams.GetModuli();
			std::vector<BigBinaryInteger> rootsOfUnity = RootsOfUnity(decomposedCyclotomicOrder, moduli);
			ILDCRTParams *decomposedParamsDCRT = new ILDCRTParams(rootsOfUnity, decomposedCyclotomicOrder, moduli, modulus);
			decomposedParams = decomposedParamsDCRT;
		}
		
		lpCryptoParamsDecomposed.SetElementParams(*decomposedParams);
		
		// Element is in Coefficient domain before performing Decompose.
		Element decomposedCipherTextElement(keySwitchedCipherTextElement.Decompose(*decomposedParams));
		
		// After decompose, switch back to CRT domain
		decomposedCipherTextElement.SwitchFormat();

		Ciphertext<Element> reducedCipherText;
		//change params
		reducedCipherText.SetCryptoParameters(lpCryptoParamsDecomposed); 
		reducedCipherText.SetElement(decomposedCipherTextElement);

		LPPrivateKeyLTV<Element> sparsePrivateKeyDecomposed(lpCryptoParamsDecomposed);
		
		Element sparsePrivateKeyDecomposedElement(sparsePrivateKeyElement.Decompose(static_cast<const ElemParams&>(*decomposedParams))); //COEFF
		sparsePrivateKeyDecomposedElement.SwitchFormat(); //EVAL
		sparsePrivateKeyDecomposedElement.SetParams(dynamic_cast<const ElemParams&>(*decomposedParams));
		sparsePrivateKeyDecomposed.SetPrivateElement(sparsePrivateKeyDecomposedElement);

		CipherTextSparseKey<Element> cipherTextSparseKey;
		cipherTextSparseKey.sparsePrivateKey = sparsePrivateKeyDecomposed;
		cipherTextSparseKey.reducedCipherText = reducedCipherText;

		algorithm.Decrypt(sparsePrivateKeyDecomposed, reducedCipherText, &ctxtd);
		std::cout << "Decrypting in RingReduce: " << std::endl;
		std::cout << ctxtd << std::endl;

		return cipherTextSparseKey;
	}

	template <class Element>
	void SHEOperations<Element>::ModReduce(Ciphertext<Element> &ciphertext, LPPrivateKeyLTV<ILVectorArray2n> &sk) {
	
		ILVectorArray2n cipherTextElement = ciphertext.GetElement();
		ILVectorArray2n skElement = sk.GetPrivateElement();

		const LPCryptoParametersLTV<Element> skCryptoParams = dynamic_cast< const LPCryptoParametersLTV<Element>& >(sk.GetCryptoParameters());
		const LPCryptoParametersLTV<Element> cipherTextCryptoParams = dynamic_cast<const LPCryptoParametersLTV<Element>&>(ciphertext.GetCryptoParameters());

 		ModReduceHelper(cipherTextElement, const_cast< LPCryptoParametersLTV<Element>& >(cipherTextCryptoParams));

		ciphertext.SetElement(cipherTextElement);

		std::vector<ILVector2n> towers = skElement.GetValues();
		towers.pop_back();
		ILVectorArray2n reducedSkElement(cipherTextElement.GetParams(), towers, Format::EVALUATION);
		sk.SetPrivateElement(reducedSkElement);

	}

	template <class Element>
	void SHEOperations<Element>::ModReduceHelper(Element &element, LPCryptoParametersLTV<Element> &cryptoParams){
	
		element.SwitchFormat();
		int length = element.GetLength();
		int lastTowerIndex = length-1;
		ILDCRTParams params(element.GetParams());
		std::vector<BigBinaryInteger> moduli = params.GetModuli();

		std::vector<BigBinaryInteger> rootsOfUnity = params.GetRootsOfUnity();
		std::vector<ILVector2n> towers = element.GetValues();

		//Fetching the last tower
		ILVector2n towerT(towers[lastTowerIndex]);
		ILVector2n d(towerT);

		std::cout << std::endl << std::endl << std::endl;

		BigBinaryInteger p(cryptoParams.GetPlaintextModulus());
		BigBinaryInteger qt(moduli[length-1]);
		BigBinaryInteger v(qt.ModInverse(p));
		BigBinaryInteger a((v * qt).ModSub(BigBinaryInteger::ONE, p*qt));
		d.SwitchModulus(p*qt);

		ILVector2n delta(d.Times(a));
		std::vector<ILVector2n> deltaDCRTTowers;
		deltaDCRTTowers.reserve(length);
		for(usint i=0; i<length; i++) {
			ILVector2n temp(delta);
			ILParams params(delta.GetParams());
			params.SetRootOfUnity(rootsOfUnity[i]);
			temp.SetParams(params);
			temp.SwitchModulus(moduli[i]);
			deltaDCRTTowers.push_back(std::move(temp));
		}

		ILVectorArray2n deltaDCRT(params, deltaDCRTTowers, Format::COEFFICIENT);
		ILVectorArray2n dprime(deltaDCRT + element);
		std::vector<BigBinaryInteger> qtInverseModQi(length-1);
		
		for(usint i=0; i<length-1; i++) {
			qtInverseModQi[i] = (qt.Compare(moduli[i]) > 0) ? (qt.Mod(moduli[i])).ModInverse(moduli[i]) : qt.ModInverse(moduli[i]);
		}

		std::vector<ILVector2n> dprimeTowers = dprime.GetValues();

		moduli.pop_back();
		rootsOfUnity.pop_back();
		towers.pop_back();
		BigBinaryVector temp;

		for(usint i=0; i<length-1; i++){
			temp = dprimeTowers[i].GetValues();
			temp = temp.ModMul(qtInverseModQi[i]);
			dprimeTowers[i].SetValues(temp, Format::COEFFICIENT);
		}
		dprimeTowers.pop_back();
		
		ElemParams  *decomposedParams = NULL; 
		ILDCRTParams *modReducedILDCRTParams = new ILDCRTParams(rootsOfUnity, params.GetCyclotomicOrder(), moduli);

		ILVectorArray2n modReducedILVA(*modReducedILDCRTParams, dprimeTowers, Format::COEFFICIENT);
		modReducedILVA.SwitchFormat();
		element = modReducedILVA;
		decomposedParams = modReducedILDCRTParams;
		cryptoParams.SetElementParams(*decomposedParams);
	}
}