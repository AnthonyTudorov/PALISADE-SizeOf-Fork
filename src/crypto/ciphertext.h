/**
* @file
* @author	TPOC: 
				Dr. Kurt Rohloff <rohloff@njit.edu>,
			Programmers: 
				Dr. Yuriy Polyakov <polyakov@njit.edu>
				Hadi Sajjadpour <ss2959@njit.edu>

* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
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
* This file contains the big binary integer functionality.
*/

#ifndef LBCRYPTO_CRYPTO_CIPHERTEXT_H
#define LBCRYPTO_CRYPTO_CIPHERTEXT_H

//Includes Section
#include "pubkeylp.h"
#include "lwecrypt.h"

#include "../utils/serializable.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	 * @brief Main ciphertext class.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class Ciphertext {
	public:

		/**
		 * Default constructor
		 */
		Ciphertext() : m_cryptoParameters(NULL), m_publicKey(NULL), m_encryptionAlgorithm(NULL) {}

		/**
		* Copy constructor
		*/
		explicit Ciphertext(const Ciphertext<Element> &ciphertext);

		/**
		* Moveable copy constructor
		*/
		Ciphertext(Ciphertext<Element> &&ciphertext); 

		/**
		 * Destructor
		 */
		~Ciphertext(){}

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		Ciphertext<Element>& operator=(const Ciphertext<Element> &rhs);

		/**
		* Moveable Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		Ciphertext<Element>& operator=(Ciphertext<Element> &&rhs);

		/**
		* Get a reference to crypto parameters.
		* @return the crypto parameters.
		*/
		const LPCryptoParameters<Element> &GetCryptoParameters() const { return *m_cryptoParameters; }

		//LPCryptoParameters<Element> &AccessCryptoParameters() const { return *m_cryptoParameters; }
		//cannot convert from 'const lbcrypto::LPCryptoParameters<Element>' to 'lbcrypto::LPCryptoParameters<Element> &'

		/**
		* Get a reference to public key.
		* @return the public key.
		*/
		const LPPublicKey<Element> &GetPublicKey() const { return *m_publicKey; }

		/**
		* Get a reference to the encryption algorithm.
		* @return the encryption alorithm.
		*/
		const LPEncryptionAlgorithm<Element> &GetEncryptionAlgorithm() const { return *m_encryptionAlgorithm; }

		/**
		* Get current estimate of estimate norm
		* @return the current estimate of ciphertext norm.
		*/
		const BigBinaryInteger &GetNorm() const { return m_norm; }

		/**
		* Get the element
		* @return the ring element.
		*/
		const Element &GetElement() const { return m_element; }

		/**
		* Sets a reference to crypto parameters.
		*
		* @param &cryptoParameters is crypto params passed by reference.
		*/
		void SetCryptoParameters(const LPCryptoParameters<Element> &cryptoParameters) { m_cryptoParameters = &cryptoParameters; }

		/**
		* Sets a reference to public key.
		*
		* @param &publicKey is public key passed by reference.
		*/
		void SetPublicKey(const LPPublicKey<Element> &publicKey) { m_publicKey = &publicKey; }

		/**
		* Sets a reference to algorithm.
		*
		* @param &encryptionAlgorithm is encryption algorithm passed by reference.
		*/
		void SetEncryptionAlgorithm(const LPEncryptionAlgorithm<Element> &encryptionAlgorithm) { m_encryptionAlgorithm = &encryptionAlgorithm; }

		/**
		* Sets ciphertext norm.
		*
		* @param &norm is ciphertext norm estimate.
		*/
		void SetNorm(const BigBinaryInteger &norm) {  m_norm = norm; }

		/**
		* Sets the data element.
		*
		* @param &element is a polynomial ring element.
		*/
		void SetElement(const Element &element) { m_element = element; }

		/**
		* Performs EvalAdd operation.
		*
		* @param &ciphertext is the element to add.
		* @return the new ciphertext.
		*/
		Ciphertext<Element> EvalAdd(const Ciphertext<Element> &ciphertext) const;

		//JSON FACILITY
		std::unordered_map <std::string, std::string> SetIdFlag(std::unordered_map <std::string, std::string> serializationMap, std::string flag) const {

			serializationMap.emplace("ID", "Ciphertext");
			serializationMap.emplace("Flag", flag);

			return serializationMap;
		}

		//JSON FACILITY
		std::unordered_map <std::string, std::string> Serialize(std::unordered_map <std::string, std::string> serializationMap, std::string fileFlag) {

			std::string jsonInputBuffer = "";
			SerializableHelper jsonHelper;

			serializationMap = this->SetIdFlag(serializationMap, fileFlag);

			//Changed to pointer to access stuff through it and treat it like an instantiation
			const LPCryptoParameters<Element> *lpCryptoParams = &this->GetCryptoParameters();
			serializationMap = lpCryptoParams->Serialize(serializationMap, "");

			serializationMap.emplace("Norm", this->GetNorm().ToString());

			serializationMap = this->GetElement().Serialize(serializationMap, "");

			/*m_serializationMapBuffer = this->GetPublicKey().Serialize(m_serializationMapBuffer, "");
			cout << "m_serializationMapBuffer size: " << m_serializationMapBuffer.size() << endl;
			jsonInputBuffer = jsonHelper.GetJsonString(m_serializationMapBuffer);
			cout << "m_serializationMapBuffer jsonInputBuffer: " << jsonInputBuffer << std::endl;
			serializationMap.emplace("PublicKey", jsonInputBuffer);*/

			return serializationMap;
		}

		//JSON FACILITY
		void Deserialize(std::unordered_map <std::string, std::string> serializationMap) {

			std::cout << "+++Setting Cyphertext.CryptoParameters: " << std::endl;
			LPCryptoParametersLWE<Element> json_cryptoParams;
			json_cryptoParams.Deserialize(serializationMap);
			this->SetCryptoParameters(json_cryptoParams);

			//YURIY's FIX
			//LPCryptoParameters<Element> *json_cryptoParams = &this->AccessCryptoParameters();
			//json_cryptoParams->Deserialize(serializationMap);

			std::cout << "&&&Set Cyphertext.CryptoParameters" << std::endl;

			std::cout << "YURIY: In Deserialize for ciphertext.h: " << this->GetCryptoParameters().GetPlaintextModulus() << std::endl;

			std::cout << "+++Setting Cyphertext.Norm: " << std::endl;
			BigBinaryInteger bbiNorm(serializationMap["Norm"]);
			this->SetNorm(bbiNorm);
			std::cout << "&&&Set Cyphertext.Norm" << std::endl;
			std::cout << "Norm " << this->GetNorm().ToString() << std::endl;

			std::cout << "+++Setting Cyphertext.Element<ILVector2n>: " << std::endl;
			Element json_ilElement;
			json_ilElement.Deserialize(serializationMap);
			this->SetElement(json_ilElement);
			std::cout << "&&&Set Cyphertext.Element<ILVector2n>" << std::endl;
		}
	
	private:

		//pointer to crypto parameters
		const LPCryptoParameters<Element> *m_cryptoParameters;

		//pointer to public key
		const LPPublicKey<Element> *m_publicKey;

		//pointer to algorithm
		const LPEncryptionAlgorithm<Element> *m_encryptionAlgorithm;

		//current value of error norm
		BigBinaryInteger m_norm;

		//data element
		Element m_element;

	};

} // namespace lbcrypto ends
#endif