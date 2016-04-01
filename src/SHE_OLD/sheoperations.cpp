
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
	Ciphertext<Element> SHEOperations<Element>::KeySwitch(const LPPrivateKey<Element> &newPrivateKey, 
			LPPrivateKey<Element> &origPrivateKey,
			DiscreteGaussianGenerator &dgg, 
			Ciphertext<Element> &origCipherText) const {

		Element keySwitchHint(KeySwitchHintGen(newPrivateKey, origPrivateKey, dgg));

		const LPCryptoParameters<Element> &cryptoParamsOriginal = origPrivateKey.GetAbstractCryptoParameters();

		const ElemParams &originalKeyParams = cryptoParamsOriginal.GetElementParams();

		Element ciphertextElement(originalKeyParams);

		ciphertextElement = origCipherText.GetElement();

		ciphertextElement = keySwitchHint * ciphertextElement;

		Ciphertext<Element> newCipherText(origCipherText);
		
		newCipherText.SetElement(ciphertextElement);
		
		return newCipherText;
	}

	template <class Element>
	LPKeySwitchHint SHEOperations<Element>::KeySwitchHintGen(const LPPrivateKey<Element> &newPrivateKey, 
			LPPrivateKey<Element> &origPrivateKey,
			DiscreteGaussianGenerator &dgg) const {
	
		const LPCryptoParameters<Element> &cryptoParamsOriginal = origPrivateKey.GetAbstractCryptoParameters();
		const ElemParams &originalKeyParams = cryptoParamsOriginal.GetElementParams();

		Element f1 = origPrivateKey.GetPrivateElement(); //add const
		Element f2 = newPrivateKey.GetPrivateElement(); //add const
		const BigBinaryInteger &p = cryptoParamsOriginal.GetPlaintextModulus();

		Element e(dgg,originalKeyParams,Format::COEFFICIENT);
		e.SwitchFormat();
		//	e.PrintValues();

		Element m(originalKeyParams);
		m = p * e;
		// std::cout << p << std::endl;
		//	m.PrintValues();
		m.ModularOne();
		//	m = m + BigBinaryInteger::ONE;
		//	m.PrintValues();

		Element newKeyInverse = f2.MultiplicativeInverse(); 

		Element keySwitchHint(originalKeyParams);
		keySwitchHint = m * f1 * newKeyInverse;
		//	test = f1 * newKeyInverse;
		//	keySwitchHint = m * f1 * newKeyInverse;
		return keySwitchHint;

	}

	template <class Element>
	CipherTextSparseKey<Element> SHEOperations<Element>::RingReduce(Ciphertext<Element> &origCipherText, 
		LPPrivateKeyLWENTRU<Element> &origPrivateKey, 
		DiscreteGaussianGenerator &dgg) const {
		
		LPAlgorithmLWENTRU<Element> algorithm;

		LPCryptoParametersLWE<Element> &lpCryptoParams = static_cast<LPCryptoParametersLWE<Element>&>(origPrivateKey.AccessCryptoParameters());

		LPPublicKeyLWENTRU<Element> pk(lpCryptoParams);

		LPPrivateKeyLWENTRU<Element> sparsePrivateKey(lpCryptoParams);
		//change sparsekeygen to not have pk
		std::cout << "SHE:Step 1" << std::endl;
		algorithm.SparseKeyGen(pk, sparsePrivateKey, dgg);
		std::cout << "SHE:Step 2" << std::endl;

		Ciphertext<Element> keySwitchedCipherText(this->KeySwitch(sparsePrivateKey, origPrivateKey, dgg, origCipherText));

		ByteArrayPlaintextEncoding ctxtd;
		algorithm.Decrypt(sparsePrivateKey, keySwitchedCipherText, &ctxtd);
		std::cout << "Decryption after key switch: " << std::endl;
		std::cout << ctxtd << std::endl;


		// ------------ END OF KEY SWITCH IN RING REDUCE -----------------------

		

		Element keySwitchedCipherTextElement = keySwitchedCipherText.GetElement();
		//changing from EVALUATION to COEFFICIENT domain before performing Decompose operation.
		keySwitchedCipherTextElement.SwitchFormat();
		// keySwitchedCipherText.SetElement(keySwitchedCipherTextElement);

		std::cout << "Ciphertext before decompose: " << std::endl;
		keySwitchedCipherTextElement.PrintValues();

		Element sparsePrivateKeyElement = sparsePrivateKey.GetPrivateElement(); //EVALUATION
		sparsePrivateKeyElement.SwitchFormat(); //COEFF
		std::cout << "Printing sparsePrivateKeyElement in coefficient format: " << std::endl;
		sparsePrivateKeyElement.PrintValues();



		LPCryptoParametersLWE<Element> lpCryptoParamsDecomposed;
		// PopulateLPCryptoParametersDecomposed(lpCryptoParams, decomposedCipherText, lpCryptoParamsDecomposed);
		lpCryptoParamsDecomposed.SetPlaintextModulus(lpCryptoParams.GetPlaintextModulus());
		lpCryptoParamsDecomposed.SetDistributionParameter(lpCryptoParams.GetDistributionParameter());
		lpCryptoParamsDecomposed.SetRelinWindow(lpCryptoParams.GetRelinWindow());

		usint decomposedCyclotomicOrder = keySwitchedCipherTextElement.GetParams().GetCyclotomicOrder()/2;
		BigBinaryInteger modulus(keySwitchedCipherTextElement.GetParams().GetModulus());
		BigBinaryInteger rootOfUnity(RootOfUnity(decomposedCyclotomicOrder, modulus));
		ElemParams  *decomposedParams = NULL; 
		std::cout<<typeid(Element).name()<<std::endl;
		if(typeid(sparsePrivateKeyElement)==typeid(ILVector2n)){
			ILParams decomposedParamsSRT(decomposedCyclotomicOrder, modulus, rootOfUnity);
			//std::cout << "New root of unity = " << decomposedParams.GetRootOfUnity() << std::endl;
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
		
		std::cout << "Ciphertext after decompose: " << std::endl;
		decomposedCipherTextElement.PrintValues();
		std::cout << "SHE:Step 3" << std::endl;
		// After decompose, switch back to CRT domain
		decomposedCipherTextElement.SwitchFormat();

		



		Ciphertext<Element> reducedCipherText;
		//change params
		reducedCipherText.SetCryptoParameters(lpCryptoParamsDecomposed); 
		reducedCipherText.SetElement(decomposedCipherTextElement);
		std::cout << "decomposedCipherText format = " << decomposedCipherTextElement.GetFormat() << std::endl;

		LPPrivateKeyLWENTRU<Element> sparsePrivateKeyDecomposed(lpCryptoParamsDecomposed);



		Element sparsePrivateKeyDecomposedElement(sparsePrivateKeyElement.Decompose(static_cast<const ElemParams&>(*decomposedParams))); //COEFF
		std::cout << "Printing decomposedSparseKey in coeff format: " << std::endl;
		sparsePrivateKeyDecomposedElement.PrintValues(); //COEFF
		sparsePrivateKeyDecomposedElement.SwitchFormat(); //EVAL
		std::cout << "sparsePrivateKeyDecomposedElement format = " << sparsePrivateKeyDecomposedElement.GetFormat() << std::endl;
		sparsePrivateKeyDecomposedElement.SetParams(dynamic_cast<const ElemParams&>(*decomposedParams));
		sparsePrivateKeyDecomposed.SetPrivateElement(sparsePrivateKeyDecomposedElement);



		Element sparsePrivateErrorElement = sparsePrivateKey.GetPrivateErrorElement();
		sparsePrivateErrorElement.SwitchFormat();
		Element sparsePrivateKeyErrorDecomposedElement(sparsePrivateErrorElement.Decompose(dynamic_cast<const ElemParams&>(*decomposedParams)));
		sparsePrivateKeyErrorDecomposedElement.SwitchFormat();
		sparsePrivateKeyErrorDecomposedElement.SetParams(dynamic_cast<const ElemParams&>(*decomposedParams));
		sparsePrivateKeyDecomposed.SetPrivateErrorElement(sparsePrivateKeyErrorDecomposedElement);

		CipherTextSparseKey<Element> cipherTextSparseKey;
		cipherTextSparseKey.sparsePrivateKey = sparsePrivateKeyDecomposed;
		// std::cout << "Decomposed plaintext modulus = " << sparsePrivateKeyDecomposed.GetCryptoParameters().GetPlaintextModulus() << std::endl;
	//	cipherTextSparseKey.sparsePrivateKey
		cipherTextSparseKey.reducedCipherText = reducedCipherText;

		algorithm.Decrypt(sparsePrivateKeyDecomposed, reducedCipherText, &ctxtd);
		std::cout << "Decrypting in RingReduce: " << std::endl;
		std::cout << ctxtd << std::endl;

		return cipherTextSparseKey;
	}

	template <class Element>
	void SHEOperations<Element>::ModReduce(Ciphertext<Element> &ciphertext, LPPrivateKeyLWENTRU<ILVectorArray2n> &sk) {
	
		ILVectorArray2n cipherTextElement = ciphertext.GetElement();
		ILVectorArray2n skElement = sk.GetPrivateElement();

		const LPCryptoParametersLWE<Element> skCryptoParams = dynamic_cast< const LPCryptoParametersLWE<Element>& >(sk.GetCryptoParameters());
		const LPCryptoParametersLWE<Element> cipherTextCryptoParams = dynamic_cast<const LPCryptoParametersLWE<Element>&>(ciphertext.GetCryptoParameters());

 		ModReduceHelper(cipherTextElement, const_cast< LPCryptoParametersLWE<Element>& >(cipherTextCryptoParams));

		ciphertext.SetElement(cipherTextElement);

		std::vector<ILVector2n> towers = skElement.GetValues();
		towers.pop_back();
		ILVectorArray2n reducedSkElement(cipherTextElement.GetParams(), towers, Format::EVALUATION);
		sk.SetPrivateElement(reducedSkElement);

		std::cout << "Root of Unity in ciphertext = " << cipherTextElement.GetParams().GetRootsOfUnity()[0] << std::endl;
		std::cout << "Root of Unity in reducedSkElement = " << reducedSkElement.GetParams().GetRootsOfUnity()[0] << std::endl;
		//ciphertext.SetElement(modReducedILVA);
		std::cout << "STEP 9: DONE WITH MOD REDUCE!" << std::endl;

	}

	template <class Element>
	void SHEOperations<Element>::ModReduceHelper(Element &element, LPCryptoParametersLWE<Element> &cryptoParams){
	
		element.SwitchFormat();
		int length = element.GetLength();
		int lastTowerIndex = length-1;
		ILDCRTParams params(element.GetParams());
		std::vector<BigBinaryInteger> moduli = params.GetModuli();

		std::vector<BigBinaryInteger> rootsOfUnity = params.GetRootsOfUnity();
		std::vector<ILVector2n> towers = element.GetValues();

		std::cout << std::endl << std::endl << std::endl;
		std::cout << "Printing the input ciphertextElement: " << std::endl;
		element.PrintValues();
		std::cout << std::endl << std::endl << std::endl;

		//Fetching the last tower
		ILVector2n towerT(towers[lastTowerIndex]);
		ILVector2n d(towerT);
		std::cout << "PRINTING d" << std::endl;
		d.PrintValues();

		std::cout << std::endl << std::endl << std::endl;

		BigBinaryInteger p(cryptoParams.GetPlaintextModulus());
		BigBinaryInteger qt(moduli[length-1]);
		BigBinaryInteger v(qt.ModInverse(p));
		std::cout << "v = " << v << std::endl;
		BigBinaryInteger a((v * qt).ModSub(BigBinaryInteger::ONE, p*qt));
		std::cout << "a = " << a <<std::endl;
		d.SwitchModulus(p*qt);

		std::cout << "Printing d after SwitchModulus: " << std::endl;
		d.PrintValues();
		ILVector2n delta(d.Times(a));
	//	d = d.Mod(p*qt);
		std::cout << "p * qt = " << p*qt << std::endl;

		delta.PrintValues();
		std::cout << std::endl << std::endl << std::endl;

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
		std::cout << "Printing deltaDCRT: " << std::endl;
		deltaDCRT.PrintValues();

		ILVectorArray2n dprime(deltaDCRT + element);
		std::cout << "Printing dprime: , expecting last tower to be zero " << std::endl;
		dprime.PrintValues();
		std::cout << std::endl << std::endl << std::endl;

		std::vector<BigBinaryInteger> qtInverseModQi(length-1);
		std::cout << "STEP 5" << std::endl;

		for(usint i=0; i<length-1; i++) {
			std::cout << "length = " << length << std::endl;
			std::cout << "qt = " << qt << std::endl;
			std::cout << "moduli[i] = " << moduli[i] << std::endl;
			qtInverseModQi[i] = (qt.Compare(moduli[i]) > 0) ? (qt.Mod(moduli[i])).ModInverse(moduli[i]) : qt.ModInverse(moduli[i]);
			std::cout << "qtInverseModQi[i]: " << qtInverseModQi[i] << std::endl;

		}
		std::cout << "STEP 6" << std::endl;
		towers[length-1].PrintValues();

		std::vector<ILVector2n> dprimeTowers = dprime.GetValues();
		for(usint i=0;i<dprimeTowers.size();i++){
			std::cout<<dprimeTowers[i].GetValues().GetModulus()<<std::endl;
		}

		moduli.pop_back();
		rootsOfUnity.pop_back();
		towers.pop_back();
		std::cout << "STEP 7" << std::endl;
		BigBinaryVector temp;
	//	modulus = modulus.DividedBy(qt);

		for(usint i=0; i<length-1; i++){
			temp = dprimeTowers[i].GetValues();
			std::cout<<temp<<std::endl;
			std::cout<<temp.GetModulus()<<std::endl;
			temp = temp.ModMul(qtInverseModQi[i]);
			std::cout<<temp<<std::endl;
			dprimeTowers[i].SetValues(temp, Format::COEFFICIENT);
			std::cout << "STEP 8: final towers: i = " << i << std::endl;
			dprimeTowers[i].PrintValues();
		}
		dprimeTowers.pop_back();
		
		std::cout << "rootsOfUnity length = " << rootsOfUnity.size() << std::endl;
		ElemParams  *decomposedParams = NULL; 
		ILDCRTParams *modReducedILDCRTParams = new ILDCRTParams(rootsOfUnity, params.GetCyclotomicOrder(), moduli);

		ILVectorArray2n modReducedILVA(*modReducedILDCRTParams, dprimeTowers, Format::COEFFICIENT);
		std::cout << "CipherText at the end of ModReduce in Coefficient Format: " << std::endl;
		modReducedILVA.PrintValues();

		modReducedILVA.SwitchFormat();

		element = modReducedILVA;

		std::cout << "CipherText at the end of ModReduce in EVAL Format: " << std::endl;
		element.PrintValues();

		decomposedParams = modReducedILDCRTParams;

		cryptoParams.SetElementParams(*decomposedParams);

	}
}