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
#include "utils/hashutil.h"

namespace lbcrypto {
	
	//Method for generating signing and verification keys
	template <class Element>
	void LPSignatureSchemeGPVGM<Element>::KeyGen(LPSignKeyGPVGM<Element>* signKey,
		LPVerificationKeyGPVGM<Element>* verificationKey) {
		//Get parameters from keys
		shared_ptr<ILParams> params = signKey->GetSignatureParameters().GetILParams();
		sint stddev = signKey->GetSignatureParameters().GetDiscreteGaussianGenerator().GetStd();
		usint base = signKey->GetSignatureParameters().GetBase();
		//Generate trapdoor based using parameters and 
		std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keyPair = RLWETrapdoorUtility<Element>::TrapdoorGen(params, stddev, base);
		//Format of vectors are changed to prevent complications in calculations 
		keyPair.second.m_e.SetFormat(EVALUATION);
		keyPair.second.m_r.SetFormat(EVALUATION);
		keyPair.first.SetFormat(EVALUATION);

		//Verification key will be set to the uniformly sampled matrix used in trapdoor
		verificationKey->SetPublicElement(keyPair.first);


		//Signing key will contain public key matrix of the trapdoor and the trapdoor matrices
		signKey->SetPrivateElement(std::pair<Matrix<Element>, RLWETrapdoorPair<Element>>(keyPair));

		seed = (PseudoRandomNumberGenerator::GetPRNG())();
	}

	//Method for signing given object
	template <class Element>
	void LPSignatureSchemeGPVGM<Element>::Sign(LPSignKeyGPVGM<Element> &signKey, const BytePlaintextEncoding &plainText,
		Signature<Matrix<Element>> *signatureText) {

		//Getting parameters for calculations
		size_t n = signKey.GetSignatureParameters().GetILParams()->GetRingDimension();
		size_t k = signKey.GetSignatureParameters().GetK();
		size_t base = signKey.GetSignatureParameters().GetBase();

		//Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
		HashUtil util;
		BytePlaintextEncoding hashedText = util.Hash(plainText, SHA_256);
		Element u(signKey.GetSignatureParameters().GetILParams(), EVALUATION, false);
		if (hashedText.size() > n) {
			hashedText.Encode(typename Element::Integer("256"), &u, 0, n);
		}
		else {
			usint remaining = n - hashedText.size();
			for (size_t i = 0;i < remaining;i++) {
				hashedText.push_back(0);
			}
			hashedText.Encode(typename Element::Integer("256"), &u);
		}
		u.SwitchFormat();


		//Getting the trapdoor, its public matrix, perturbation matrix and gaussian generator to use in sampling
		Matrix<Element> A = signKey.GetPrivateElement().first;
		RLWETrapdoorPair<Element> T = signKey.GetPrivateElement().second;
		//double stddev = signKey.GetSignatureParameters().GetDiscreteGaussianGenerator().GetStd();
		typename Element::DggType & dgg = signKey.GetSignatureParameters().GetDiscreteGaussianGenerator();


		typename Element::DggType & dggLargeSigma = signKey.GetSignatureParameters().GetDiscreteGaussianGeneratorLargeSigma();
		Matrix<Element> zHat = RLWETrapdoorUtility<Element>::GaussSamp(n,k,A,T,u,dgg,dggLargeSigma,base);
		signatureText->SetElement(zHat);

	}

	//Method for signing given object
	template <class Element>
	shared_ptr<Matrix<Element>> LPSignatureSchemeGPVGM<Element>::SampleOffline(LPSignKeyGPVGM<Element> &signKey) {

		//Getting parameters for calculations
		size_t n = signKey.GetSignatureParameters().GetILParams()->GetRingDimension();
		size_t k = signKey.GetSignatureParameters().GetK();
		size_t base = signKey.GetSignatureParameters().GetBase();

		//Getting the trapdoor and gaussian generatorw to use in sampling
		RLWETrapdoorPair<Element> T = signKey.GetPrivateElement().second;
		typename Element::DggType & dgg = signKey.GetSignatureParameters().GetDiscreteGaussianGenerator();
		typename Element::DggType & dggLargeSigma = signKey.GetSignatureParameters().GetDiscreteGaussianGeneratorLargeSigma();

		return RLWETrapdoorUtility<Element>::GaussSampOffline(n, k, T, dgg, dggLargeSigma, base);

	}

	//Method for signing given object
	template <class Element>
	void LPSignatureSchemeGPVGM<Element>::SignOnline(LPSignKeyGPVGM<Element> &signKey, 
		shared_ptr<Matrix<Element>> perturbationVector,	const BytePlaintextEncoding &plainText,
		Signature<Matrix<Element>> *signatureText) {

		//Getting parameters for calculations
		size_t n = signKey.GetSignatureParameters().GetILParams()->GetRingDimension();
		size_t k = signKey.GetSignatureParameters().GetK();
		size_t base = signKey.GetSignatureParameters().GetBase();

		//Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
		HashUtil util;
		BytePlaintextEncoding hashedText = util.Hash(plainText, SHA_256);
		Element u(signKey.GetSignatureParameters().GetILParams(), EVALUATION, false);
		if (hashedText.size() > n) {
			hashedText.Encode(typename Element::Integer("256"), &u, 0, n);
		}
		else {
			BytePlaintextEncoding seed_in = plainText;
			char seed_bits;
			while (seed_in.size() < n) {
				BytePlaintextEncoding rand = util.Hash(seed_in, SHA_256);
				seed_bits = (seed >> 24)& 0xFF;
				rand.push_back(seed_bits);
				seed_bits = (seed >> 16) & 0xFF;
				rand.push_back(seed_bits);
				seed_bits = (seed >> 8) & 0xFF;
				rand.push_back(seed_bits);
				seed_bits = (seed) & 0xFF;
				rand.push_back(seed_bits);
				BytePlaintextEncoding seed_out;
				seed_out.push_back(1);
				for (size_t i = 0;i < seed_in.size();i++) {
					seed_out.push_back(seed_in[i]);
				}
				for (size_t j = 0;j < rand.size(); j++) {
					seed_out.push_back(rand[j]);
				}
				seed_in = seed_out;
			}
			seed_in.Encode(typename Element::Integer("256"), &u,0,n);
		}
		u.SwitchFormat();


		//Getting the trapdoor, its public matrix, perturbation matrix and gaussian generator to use in sampling
		Matrix<Element> A = signKey.GetPrivateElement().first;
		RLWETrapdoorPair<Element> T = signKey.GetPrivateElement().second;
		//double stddev = signKey.GetSignatureParameters().GetDiscreteGaussianGenerator().GetStd();
		typename Element::DggType & dgg = signKey.GetSignatureParameters().GetDiscreteGaussianGenerator();

		Matrix<Element> zHat = RLWETrapdoorUtility<Poly>::GaussSampOnline(n, k, A, T, u, dgg, perturbationVector, base);
		signatureText->SetElement(zHat);

	}

	
	//Method for verifying given object & signature
	template <class Element>
	bool LPSignatureSchemeGPVGM<Element>::Verify(LPVerificationKeyGPVGM<Element> &verificationKey,
		const Signature<Matrix<Element>> &signatureText,
		const BytePlaintextEncoding & plainText) {
		size_t n = verificationKey.GetSignatureParameters().GetILParams()->GetRingDimension();

		//Encode the text into a vector so it can be used in verification process. TODO: Adding some kind of digestion algorithm
		HashUtil util;
		BytePlaintextEncoding hashedText = util.Hash(plainText, SHA_256);
		Element u(verificationKey.GetSignatureParameters().GetILParams());
		if (hashedText.size() > n) {
			hashedText.Encode(typename Element::Integer("256"), &u, 0, n);
		}
		else {
			BytePlaintextEncoding seed_in = plainText;
			char seed_bits;
			while (seed_in.size() < n) {
				BytePlaintextEncoding rand = util.Hash(seed_in, SHA_256);
				seed_bits = (seed >> 24) & 0xFF;
				rand.push_back(seed_bits);
				seed_bits = (seed >> 16) & 0xFF;
				rand.push_back(seed_bits);
				seed_bits = (seed >> 8) & 0xFF;
				rand.push_back(seed_bits);
				seed_bits = (seed) & 0xFF;
				rand.push_back(seed_bits);
				BytePlaintextEncoding seed_out;
				seed_out.push_back(1);
				for (size_t i = 0;i < seed_in.size();i++) {
					seed_out.push_back(seed_in[i]);
				}
				for (size_t j = 0;j < rand.size(); j++) {
					seed_out.push_back(rand[j]);
				}
				seed_in = seed_out;
			}
			seed_in.Encode(typename Element::Integer("256"), &u, 0, n);
		}
		u.SwitchFormat();

		//Multiply signature with the verification key
		Matrix<Element> A = verificationKey.GetPublicElement();
		Matrix<Element> z = signatureText.GetElement();
		Matrix<Element> R = A*z;

		//Check the verified vector is actually the encoding of the object
		Element r = R(0, 0);
		return r == u;
	}

}
#endif
