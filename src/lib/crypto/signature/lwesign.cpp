/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers:
*		K.Doruk Gur <kg365@njit.edu>
* @version 00_01
*
* @section LICENSE
*
* Copyright (c) 2016, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
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
* This code provides the utility for GPV Ring-LWE signature scheme with trapdoors. The scheme implemented can be found in the paper https://eprint.iacr.org/2013/297.pdf. Construction 1 of the section 3.2 is used in this implementation. 
*/
#ifndef _SRC_LIB_CRYPTO_SIGNATURE_LWESIGN_CPP
#define _SRC_LIB_CRYPTO_SIGNATURE_LWESIGN_CPP
#include "lwesign.h"
#include "../../lattice/trapdoor.h"

namespace lbcrypto {
	
	//Method for generating signing and verification keys
	template <class Element>
	void LPSignatureSchemeGPV<Element>::KeyGen(LPSignKeyGPV<Element>* signKey,
		LPVerificationKeyGPV<Element>* verificationKey) {
		//Get parameters from keys
		ILParams params = signKey->GetSignatureParameters().GetILParams();
		sint stddev = signKey->GetSignatureParameters().GetDiscreteGaussianGenerator().GetStd();
		
		//Generate trapdoor based using parameters and 
		std::cout << "Trapdoor generation started" << std::endl;
		std::pair<Matrix<ILVector2n>, RLWETrapdoorPair<ILVector2n>> keyPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev);
		std::cout << "Trapdoor generated" << std::endl;
		//Format of vectors are changed to prevent complications in calculations 
		keyPair.second.m_e.SetFormat(EVALUATION);
		keyPair.second.m_r.SetFormat(EVALUATION);
		keyPair.first.SetFormat(EVALUATION);
		
		//Verification key will be set to the uniformly sampled matrix used in trapdoor
		verificationKey->SetPublicElement(keyPair.first);
		
		//Calculate perturbation matrix once so multiple signatures won't be slowed down by this step. Refer to the paper for clarification on the usage of this matrix.
		const BigBinaryInteger & q = verificationKey->GetSignatureParameters().GetILParams().GetModulus();
		size_t n = verificationKey->GetSignatureParameters().GetILParams().GetCyclotomicOrder() / 2;
		double logTwo = log(q.ConvertToDouble() - 1.0) / log(2) + 1.0;
		size_t k = (usint)floor(logTwo);
		double s = 40 * std::sqrt(n*(2+k));
		Matrix<LargeFloat> sigmaSqrt([]() { return make_unique<LargeFloat>(); }, n*2, n*2);
		RLWETrapdoorUtility::PerturbationMatrixGenAlt(n,k, keyPair.first, keyPair.second, s, &sigmaSqrt);
		//Signing key will contain perturbation matrix, public key matrix of the trapdoor and the trapdoor matrices
		signKey->SetPrivateElement(std::pair<Matrix<LargeFloat>, std::pair<Matrix<ILVector2n>, RLWETrapdoorPair<ILVector2n>>>(sigmaSqrt,keyPair));
	}
	
	//Method for signing given object
	template <class Element>
	void LPSignatureSchemeGPV<Element>::Sign(LPSignKeyGPV<Element> &signKey, const Plaintext &plainText,
		Signature<Matrix<Element>> *signatureText) {
		
		//Getting parameters for calculations
		const BigBinaryInteger & q = signKey.GetSignatureParameters().GetILParams().GetModulus();
		size_t n = signKey.GetSignatureParameters().GetILParams().GetCyclotomicOrder() / 2;
		double logTwo = log(q.ConvertToDouble() - 1.0) / log(2) + 1.0;
		size_t k = (usint)floor(logTwo);
		
		//Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
		ILVector2n u(signKey.GetSignatureParameters().GetILParams(),EVALUATION,false);
		plainText.Encode(q, &u);
		u.SwitchFormat();

		
		//Getting the trapdoor, its public matrix, perturbation matrix and gaussian generator to use in sampling
		RingMat A = signKey.GetPrivateElement().second.first;
		RLWETrapdoorPair<ILVector2n> T = signKey.GetPrivateElement().second.second;
		double stddev = signKey.GetSignatureParameters().GetDiscreteGaussianGenerator().GetStd();
		DiscreteGaussianGenerator & dgg = signKey.GetSignatureParameters().GetDiscreteGaussianGenerator();
		Matrix <LargeFloat> sigmaSqrt = signKey.GetPrivateElement().first;
		
		//Generating the signature via Gaussian sampling using the values above
		Matrix<ILVector2n> zHat = RLWETrapdoorUtility::GaussSamp(n, k, A, T, sigmaSqrt,u, stddev, dgg );
		signatureText->SetElement(zHat);

	}
	//Method for verifying given object & signature
	template <class Element>
	bool LPSignatureSchemeGPV<Element>::Verify(LPVerificationKeyGPV<Element> &verificationKey,
		const Signature<Matrix<Element>> &signatureText,
		const Plaintext & plainText) {
		const BigBinaryInteger & q = verificationKey.GetSignatureParameters().GetILParams().GetModulus();
		
		//Encode the text into a vector so it can be used in verification process. TODO: Adding some kind of digestion algorithm
		ILVector2n u(verificationKey.GetSignatureParameters().GetILParams());
		plainText.Encode(q, &u);
		u.SwitchFormat();
		
		//Multiply signature with the verification key
		RingMat A = verificationKey.GetPublicElement();
		RingMat z = signatureText.GetElement();
		RingMat R = A*z;
		
		//Check the verified vector is actually the encoding of the object
		ILVector2n r = R(0, 0);
		return r == u;
	}

}
#endif
