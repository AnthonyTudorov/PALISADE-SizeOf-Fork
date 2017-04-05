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

#ifndef _SRC_LIB_CRYPTO_SIGNATURE_LWESIGN_H
#define _SRC_LIB_CRYPTO_SIGNATURE_LWESIGN_H
#include "../sampling/trapdoor.h"
#include "../sampling/trapdoor.cpp"
#include "encoding/byteplaintextencoding.h"

namespace lbcrypto {

	/*
	*  @brief Templated class for holding signatures. Although the scheme only valid for one type of scheme, implementation is done considering possible future
	*  @tparam is the ring element
	*/
	template <class Element>
	class Signature {
	public:
		/**
		* Default constructor
		*/
		Signature() { m_element = nullptr; }

		/**
		*Method for setting the element in signature
		*
		*@param element Element to be set as the signature
		*/
		void SetElement(Element element) {
			if (m_element != nullptr) {
				delete m_element;
			}
			m_element = new Element(element);
		}
		/**
		*Method for getting the element in signature
		*
		*@return the element held as signature
		*/
		const Element& GetElement() const { return *m_element; }

		/**
		*Destructor
		*/
		~Signature() { delete m_element; }
	private:
		Element* m_element;
	};

	/**
	* @brief Abstract class for signing keys, not implemented currently
	*
	* @tparam is the ring element
	*/
	template <class Element>
	class LPSignKey {
	public:
		/**
		*Method for getting the element in key
		*
		*@return the element held as key
		*/
		virtual const Element &GetPrivateElement();
		/**
		*Method for setting the element key
		*
		*@param element Element to be set as the key
		*/
		virtual void SetPrivateElement(Element element);
	};

	/**
	*  @brief Abstract class for verification keys, not implemented currently
	*  @tparam is the ring element
	*/
	template <class Element>
	class LPVerificationKey {
	public:
		/**
		* Method for getting the element in key
		*
		* @return the element held as key
		*/
		virtual const Element & GetPublicElement();

		/**
		*Method for setting the element key
		*
		*@param element Element to be set as the key
		*/
		virtual void SetPublicElement(const Element& element);
	};


	/**
	* @brief  Class holding parameters required for calculations in signature schemes
	*/
	class LPSignatureParameters {
	public:
		/**
		*Method for setting the ILParams held in this class
		*
		*@param params Parameters to be held, used in ILVector construction
		*/
		void SetElemParams(shared_ptr<ILParams> params) { 
			m_params = params; 
			const BigBinaryInteger & q = params->GetModulus();
			size_t n = params->GetCyclotomicOrder() / 2;
			double logTwo = log(q.ConvertToDouble() - 1.0) / log(2) + 1.0;
			size_t k = (usint)floor(logTwo);
			double c = 2 * SIGMA;
			double s = SPECTRAL_BOUND(n, k);
			dggLargeSigma = ILVector2n::DggType(sqrt(s * s - c * c));
		};

		/**
		*Method for accessing the ILParams held in this class
		*
		*@return Parameters held
		*/
		shared_ptr<ILParams> GetILParams() { return m_params; }

		/**
		*Method for accessing the DiscreteGaussianGenerator object held in this class
		*
		*@return DiscreteGaussianGenerator object held
		*/
		ILVector2n::DggType & GetDiscreteGaussianGenerator() { return dgg; }

		/**
		*Method for accessing the DiscreteGaussianGenerator object held in this class
		*
		*@return DiscreteGaussianGenerator object held
		*/
		ILVector2n::DggType & GetDiscreteGaussianGeneratorLargeSigma() { return dggLargeSigma; }

		/**
		*Default constructor
		*/
		LPSignatureParameters() {}
		/**
		*Constructor
		*@param params Parameters used in ILVector construction
		*@param dgg DiscreteGaussianGenerator used in sampling
		*/
		LPSignatureParameters(shared_ptr<ILParams> params, ILVector2n::DggType dgg) : dgg(dgg) {
			m_params = params;
			const BigBinaryInteger & q = params->GetModulus();
			size_t n = params->GetCyclotomicOrder() / 2;
			double logTwo = log(q.ConvertToDouble() - 1.0) / log(2) + 1.0;
			size_t k = (usint)floor(logTwo);
			double c = 2 * SIGMA;
			double s = SPECTRAL_BOUND(n, k);
			dggLargeSigma = ILVector2n::DggType(sqrt(s * s - c * c));
		}


	private:
		shared_ptr<ILParams> m_params;
		ILVector2n::DggType dgg;
		ILVector2n::DggType dggLargeSigma;
	};

	/**
	*  @brief Class holding signing key for Ring LWE variant of GPV signing algorithm with GM17 improvements. The values held in this class are trapdoor and public key
	*  @tparam is the ring element
	*/
	template <class Element>
	class LPSignKeyGPVGM {
	public:
		/**
		* Default constructor
		*/
		LPSignKeyGPVGM() { m_sk = nullptr; }

		/**Constructor
		*
		* @param signParams parameters used in signing process
		*/
		LPSignKeyGPVGM(LPSignatureParameters&signParams) {
			this->SetSignatureParameters(signParams);
			m_sk = nullptr;
		}

		/**
		*Destructor
		*/
		~LPSignKeyGPVGM() {
			delete m_sk;
		}

		/**
		*Method for accessing parameters used in signing process
		*
		*@return Parameters used in signing
		*/
		LPSignatureParameters & GetSignatureParameters() { return m_signParameters; }

		/**
		*Method for accessing key in signing process
		*
		*@return Key used in signing
		*/
		const  std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> & GetPrivateElement() const { return *m_sk; }
		/**
		*Method for setting parameters used in signing process
		*
		*@param signParams Parameters used in signing
		*/
		void SetSignatureParameters(const LPSignatureParameters & signParams) { m_signParameters = signParams; }
		/**
		*Method for setting the private key used in the signing process
		*
		*@param &x a pair of public key and trapdoor used for signing
		*/
		void SetPrivateElement(const std::pair<Matrix<Element>, RLWETrapdoorPair<Element>>& x) {
			if (m_sk != nullptr) {
				delete m_sk;
			}
			m_sk = new std::pair<Matrix<Element>, RLWETrapdoorPair<Element>>(x);
		}
	private:
		LPSignatureParameters m_signParameters;
		std::pair<Matrix<Element>, RLWETrapdoorPair<Element>>* m_sk;
	};

	/**
	* @brief Class holding verification key for Ring LWE variant of GPV signing algorithm with GM17 improvements. The value held in this class is the  public key of the trapdoor
	* @tparam is the ring element
	*/
	template <class Element>
	class LPVerificationKeyGPVGM {
	public:

		/**
		*  Default constructor
		*/
		LPVerificationKeyGPVGM() { m_vk = nullptr; }

		/**
		* Constructor
		* @param signParams parameters used in verification process
		*/
		LPVerificationKeyGPVGM(LPSignatureParameters &signParams) {
			this->SetSignatureParameters(signParams);
			m_vk = nullptr;
		}

		/**
		*  Destructor
		*/
		~LPVerificationKeyGPVGM() {
			delete m_vk;
		}

		/**
		*Method for accessing parameters used in verification process
		*
		*@return Parameters used in verification
		*/
		LPSignatureParameters & GetSignatureParameters() { return m_signParameters; }

		/**
		*Method for accessing key in verification process
		*
		*@return Key used in verification
		*/
		const Matrix<Element> & GetPublicElement() const { return *m_vk; }

		/**
		* Method for setting parameters used in verification process
		*
		* @param &signParams Parameters used in verification
		*/
		void SetSignatureParameters(const LPSignatureParameters & signParams) { m_signParameters = signParams; }

		/**
		* Method for setting key used in verification process
		*
		* @param x Key used in verification
		*/
		void SetPublicElement(const Matrix<Element>& x) {
			if (m_vk != nullptr) {
				delete m_vk;
			}
			m_vk = new Matrix<Element>(x);
		}
	private:
		LPSignatureParameters m_signParameters;
		Matrix<Element>* m_vk;
	};
	
	/**
	*@brief Implementation of Ring LWE variant of GPV signature scheme. Currently it supports only one type of vectors, therefore it is not templated
	*  @tparam is the ring element
	*/
	template <class Element>
	class LPSignatureSchemeGPVGM {
	public:
		/**
		* Default constructor
		*/
		LPSignatureSchemeGPVGM() {}

		/**
		*Method for signing given text
		*@param signKey private signing key
		*@param plainText encoding of the text to be signed
		*@param signatureText signature generated after the signing process - output of the function
		*/
		void Sign(LPSignKeyGPVGM<Element> &signKey, const BytePlaintextEncoding &plainText,
			Signature<Matrix<Element>>*signatureText);

		/**
		*Method for verifying given text & signature
		*
		*@param verificationKey public verification key
		*@param signatureText signature to be verified
		*@param plainText encoding of the text to be verified
		*@return result of the verification process
		*/
		bool Verify(LPVerificationKeyGPVGM<Element> &verificationKey,
			const Signature<Matrix<Element>> &signatureText,
			const BytePlaintextEncoding & plainText);

		/**
		*
		*Method for generating signing and verification keys
		*
		*@param signKey private signing key generated after trapdoor & perturbation matrix - output of the function
		*@param verificationKey public verification key generated after trapdoor - output of the function
		*/
		void KeyGen(LPSignKeyGPVGM<Element> *signKey,
			LPVerificationKeyGPVGM<Element> *verificationKey);
	};
}
#endif
