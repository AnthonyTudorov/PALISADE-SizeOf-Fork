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
#include "../palisade.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	//JSON FACILITY - Forward declaration for temporary fix of lweautomorph.cpp Linux compilation error
	template <class Element>
	class LPCryptoParametersLTV;

	template <class Element>
	class LPCryptoParametersStehleSteinfeld;

	template <class Element>
	class LPCryptoParametersBV;

	/**
	 * @brief Main ciphertext class.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class Ciphertext : public Serializable {
	public:

		/**
		 * Default constructor
		 */
		Ciphertext() : m_norm(BigBinaryInteger::ZERO) {}

		Ciphertext(CryptoContext<Element> cc) : cryptoContext(cc), m_norm(BigBinaryInteger::ZERO) {}

		/**
		* Copy constructor
		*/
		Ciphertext(const Ciphertext<Element> &ciphertext);

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
		const CryptoContext<Element> &GetCryptoContext() const { return cryptoContext; }

		/**
		* Get a reference to crypto parameters.
		* @return the crypto parameters.
		*/
		const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return cryptoContext.GetCryptoParameters(); }

		/**
		* Get a reference to the encryption algorithm.
		* @return the encryption alorithm.
		*/
		const LPPublicKeyEncryptionScheme<Element> &GetEncryptionAlgorithm() const { return cryptoContext.GetEncryptionAlgorithm(); }

		/**
		* Get current estimate of estimate norm
		* @return the current estimate of ciphertext norm.
		*/
		const BigBinaryInteger &GetNorm() const { return m_norm; }

		/**
		* Get the first element
		* @return the ring element.
		*/
		const Element &GetElement() const { 
			if (m_elements.size() > 0)
				return m_elements[0]; 
			else
			{
				std::string errMsg = "No elements are current stored in the ciphertext";
				throw std::runtime_error(errMsg);
			}
		}

		/**
		* Get all elements in the ciphertext
		* @return the ring element.
		*/
		const std::vector<Element> &GetElements() const { return m_elements; }

		/**
		* Set crypto parameters for this ciphertext.
		*
		* @param cryptoParameters
		*
		*/
		void SetCryptoParameters(const LPCryptoParameters<Element> *cryptoParameters) {
			throw std::logic_error("fix my setting parameters!");
//			if( m_cryptoParameters != 0 )
//				throw std::logic_error("Crypto parameters can not be changed in existing ciphertext");
//			m_cryptoParameters = cryptoParameters;
		}

		/**
		* Sets ciphertext norm.
		*
		* @param &norm is ciphertext norm estimate.
		*/
		void SetNorm(const BigBinaryInteger &norm) {  m_norm = norm; }

		/**
		* Sets the first data element.
		*
		* @param &element is a polynomial ring element.
		*/
		void SetElement(const Element &element) { 
			if (m_elements.size() > 0)
				m_elements[0] = element;
			else
				m_elements.push_back(element);
		}

		/**
		* Sets the data elements.
		*
		* @param &element is a polynomial ring element.
		*/
		void SetElements(const std::vector<Element> &elements) { m_elements = elements; }

		/**
		* Performs EvalAdd operation.
		*
		* @param &ciphertext is the element to add.
		* @return the new ciphertext.
		*/
		Ciphertext<Element> EvalAdd(const Ciphertext<Element> &ciphertext) const;
	
		//JSON FACILITY
		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const;

		/**
		* Higher level info about the serialization is saved here
		* @param serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized* serObj, const std::string flag) const;

		/**
		* Populate the object from the deserialization of the Setialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj);

	private:

		CryptoContext<Element>	cryptoContext;

		//current value of error norm
		BigBinaryInteger m_norm;

		//data element
		std::vector<Element> m_elements;

	};

} // namespace lbcrypto ends
#endif
