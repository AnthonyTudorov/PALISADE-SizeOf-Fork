/**0
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
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
 * This code provides the core proxy re-encryption functionality.
 */

#ifndef LBCRYPTO_CRYPTO_LWECRYPT_H
#define LBCRYPTO_CRYPTO_LWECRYPT_H

//Includes Section
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../math/backend.h"
#include "pubkeylp.h"
#include "ciphertext.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	/**
	 * @brief Template for crypto parameters.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPCryptoParametersLWE : public LPCryptoParametersImpl<Element> {
		public:
			
			/**
			 * Constructor that initializes all values to 0.
			 */
			LPCryptoParametersLWE() {
				//m_params = new ElementParams();commented out by Gyana
				//m_plaintextModulus = new BigBinaryInteger();commented out by Gyana 
				m_distributionParameter = 0.0f;
				m_assuranceMeasure = 0.0f;
				m_securityLevel = 0.0f;
				m_relinWindow = 1;
				m_depth = 0;
			}

			/**
			 * Constructor that initializes values.
			 *
			 * @param &params element parameters.
			 * @param &plaintextModulus plaintext modulus.
			 * @param distributionParameter noise distribution parameter.
			 * @param assuranceMeasure assurance level.
			 * @param securityLevel security level.
			 * @param relinWindow the size of the relinearization window.
			 * @param depth depth which is set to 1.
			 */
			LPCryptoParametersLWE(const ElemParams &params,
				const BigBinaryInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				int depth = 1)
			{
				m_params = params;
				m_plaintextModulus = plaintextModulus;
				m_distributionParameter = distributionParameter;
				m_assuranceMeasure = assuranceMeasure;
				m_securityLevel = securityLevel;
				m_relinWindow = relinWindow;
				m_depth = depth;
			}

			/**
			* Destructor
			*/
			~LPCryptoParametersLWE() {
			}
			
			/**
			 * Initialization methods.
			 *
			 * @param &params element parameters.
			 * @param &plaintextModulus plaintext modulus.
			 * @param distributionParameter noise distribution parameter.
			 * @param assuranceMeasure assurance level.
			 * @param securityLevel security level.
			 * @param relinWindow the size of the relinearization window.
			 * @param depth depth which is set to 1.
			 */
			void Initialize(const ElemParams &params,
				const BigBinaryInteger &plaintextModulus,  
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				int depth = 1)
			{
				m_params = params;
				m_plaintextModulus = plaintextModulus;
				m_distributionParameter = distributionParameter;
				m_assuranceMeasure = assuranceMeasure;
				m_securityLevel = securityLevel;
				m_relinWindow = relinWindow;
				m_depth = depth;
			}
			
			/**
			 * Returns the value of plaintext modulus p
			 *
			 * @return the plaintext modulus.
			 */
			const BigBinaryInteger &GetPlaintextModulus() const {return  m_plaintextModulus;}
			
			/**
			 * Returns the value of standard deviation r for discrete Gaussian distribution
			 *
			 * @return the standard deviation r.
			 */
			float GetDistributionParameter() const {return m_distributionParameter;}
			
			/**
			 * Returns the values of assurance measure alpha
			 *
			 * @return the assurance measure.
			 */
			float GetAssuranceMeasure() const {return m_assuranceMeasure;}
			
			/**
			 * Returns the value of root Hermite factor security level /delta.
			 *
			 * @return the root Hermite factor /delta.
			 */
			float GetSecurityLevel() const {return m_securityLevel;}

			/**
			* Returns the value of relinearization window.
			*
			* @return the relinearization window.
			*/
			usint GetRelinWindow() const { return m_relinWindow; }
			
			/**
			 * Returns the value of computation depth d
			 *
			 * @return the computation depth supported d.
			 */
			int GetDepth() const {return m_depth;}
			
			/**
			 * Returns the reference to IL params
			 *
			 * @return the ring element parameters.
			 */
			const ElemParams &GetElementParams() const { return *m_params; }

			//@Set Properties
			
			/**
			 * Sets the value of plaintext modulus p
			 */
			void SetPlaintextModulus(const BigBinaryInteger &plaintextModulus) {m_plaintextModulus = plaintextModulus;}
			
			/**
			 * Sets the value of standard deviation r for discrete Gaussian distribution
			 */
			void SetDistributionParameter(float distributionParameter) {m_distributionParameter = distributionParameter;}
			
			/**
			 * Sets the values of assurance measure alpha
			 */
			void SetAssuranceMeasure(float assuranceMeasure) {m_assuranceMeasure = assuranceMeasure;}
			
			/**
			 * Sets the value of security level /delta
			 */
			void SetSecurityLevel(float securityLevel) {m_securityLevel = securityLevel;}

			/**
			* Sets the value of relinearization window
			*/
			void SetRelinWindow(usint relinWindow) { m_relinWindow = relinWindow; }
			
			/**
			 * Sets the value of supported computation depth d
			 */
			void SetDepth(int depth) {m_depth = depth;}
			
			/**
			 * Sets the reference to element params
			 */
			void SetElementParams(ElemParams &params) { m_params = &params; }
			
			/**
			 * Validates the parameters of cryptosystem up to a certain level will be implemented later
			 */
			bool Validate(unsigned int level);

			
			/**
			 * Checks the correctness of selected parameters will be implemented later
			 */
			bool ValidateCorrectness(unsigned int level, float assuranceMeasure);
						
			/**
			 * Checks whether the selected parameters satisfy the security requirement for specified security level will be implemented later
			 */
			bool ValidateSecurity(unsigned int level, float securityLevel);
			
			//Represent the lattice in binary format
			//void DecodeElement(const Element &element, byte *text) const {element.DecodeElement(text,GetPlaintextModulus());}
		
			//Convert binary string to lattice format
			//void EncodeElement(const byte *encoded, size_t byteCount, Element& element) {element.EncodeElement(encoded,byteCount,GetPlaintextModulus());}

			//JSON FACILITY
			/**
			* Implemented by this object only for inheritance requirements of abstract class Serializable.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			* @return map passed in.
			*/
			std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

			//JSON FACILITY
			/**
			* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
			* Invokes nested serialization of ILParams.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			* @return map updated with the attribute name value pairs required to serialize this object.
			*/
			std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

			//JSON FACILITY
			/**
			* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
			* Invokes nested deserialization of ILParams.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			*/
			void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);

		private:
			//element-specific parameters
			ElemParams *m_params;
			//plaintext modulus p
			BigBinaryInteger m_plaintextModulus;
			//standard deviation in Discrete Gaussian Distribution
			float m_distributionParameter;
			//assurance measure w
			float m_assuranceMeasure;
			//root Hermite value /delta
			float m_securityLevel;
			//relinearization window
			usint m_relinWindow;
			//depth of computations; used for FHE
			int m_depth;
	};

	/**
	 * @brief Public key implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyLWENTRU : public LPPublicKeyImpl<Element>{
		public:

			/**
			* Default constructor
			*/

			LPPublicKeyLWENTRU() {}

			/**
			* Basic constructor for setting crypto params
			*
			* @param cryptoParams is the reference to cryptoParams
			*/

			LPPublicKeyLWENTRU(LPCryptoParameters<Element> &cryptoParams) {
				this->SetCryptoParameters(&cryptoParams);
			}

			//Uses the LPCryptoParametersLWE instance
			/*void Initialize(const LPCryptoParametersLWE<Element,ElementParams> &params, 
				const Element &generatedElement, 
				const Element &publicElement)
			{
				AccessCryptoParameters() = params;
				SetGeneratedElement(generatedElement);
				SetPublicElement(publicElement);
			}*/

			//JSON FACILITY
			/**
			* Sets the ID and Flag attribute values for use in serializing this object to a JSON file.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			* @return map updated with ID and Flag attribute values.
			*/
			std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

			//JSON FACILITY
			/**
			* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
			* Invokes nested serialization of LPCryptoParametersLWE, ILParams, ILVector2n, and BigBinaryVector.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			* @return map updated with the attribute name value pairs required to serialize this object.
			*/
			std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

			//JSON FACILITY
			/**
			* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
			* Invokes nested deserialization of LPCryptoParametersLWE, ILParams, ILVector2n, and BigBinaryVector.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			*/
			void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);
	};

	/**
	* @brief Evaluation/proxy key implementation template for Ring-LWE NTRU-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyLWENTRU : public LPEvalKeyImpl<Element>{
	public:

		/**
		* Default constructor
		*/

		LPEvalKeyLWENTRU() {}

		/**
		* Basic constructor for setting crypto params
		*
		* @param cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyLWENTRU(LPCryptoParameters<Element> &cryptoParams) {
			this->SetCryptoParameters(&cryptoParams);
		}

		//JSON FACILITY
		/**
		* Sets the ID and Flag attribute values for use in serializing this object to a JSON file.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @return map updated with ID and Flag attribute values.
		*/
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

		//JSON FACILITY
		/**
		* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
		* Invokes nested serialization of LPCryptoParametersLWE, ILParams, ILVector2n, and BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @return map updated with the attribute name value pairs required to serialize this object.
		*/
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

		//JSON FACILITY
		/**
		* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
		* Invokes nested deserialization of LPCryptoParametersLWE, ILParams, ILVector2n, and BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		*/
		void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);
	};

	/**
	 * @brief Private key implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPrivateKeyLWENTRU : public LPPrivateKeyImpl<Element>{
		public:

			/**
			* Default constructor
			*/

			LPPrivateKeyLWENTRU() {}

			/**
			* Basic constructor for setting crypto params
			*
			* @param cryptoParams is the reference to cryptoParams
			*/

			LPPrivateKeyLWENTRU(LPCryptoParametersLWE<Element> &cryptoParams) {
				this->SetCryptoParameters(&cryptoParams);
			}
			
			//Uses the LPCryptoParametersLWE instance
			/*void Initialize(const LPCryptoParametersLWE<Element,ElementParams> &params, 
				const Element &privateElement)
			{
				AccessCryptoParameters() = params;
				SetPrivateElement(privateElement);
			}*/

			/**
			 * Implements the procedure to compute the public key using the current private key
			 * The formula is h = p*g*f^(-1) using standard NTRU notation
			 *
			 * @param &pub a public key.
			 */
			void MakePublicKey(LPPublicKey<Element> &pub) const
			{
				pub.SetPublicElement(this->GetCryptoParameters().GetPlaintextModulus()*this->GetPrivateErrorElement()*this->GetPrivateElement().MultiplicativeInverse());
			}

			//JSON FACILITY
			/**
			* Sets the ID and Flag attribute values for use in serializing this object to a JSON file.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			* @return map updated with ID and Flag attribute values.
			*/
			std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

			//JSON FACILITY
			/**
			* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
			* Invokes nested serialization of LPCryptoParametersLWE, ILParams, ILVector2n, and BigBinaryVector.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			* @return map updated with the attribute name value pairs required to serialize this object.
			*/
			std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

			//JSON FACILITY
			/**
			* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
			* Invokes nested deserialization of LPCryptoParametersLWE, ILParams, ILVector2n, and BigBinaryVector.
			*
			* @param serializationMap stores this object's serialized attribute name value pairs.
			*/
			void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);
	};

	/**
	 * @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAlgorithmLWENTRU : public LPEncryptionAlgorithm<Element>{
		public:

			/**
			 * Method for encrypting plaintext using Ring-LWE NTRU
			 *
			 * @param &publicKey public key used for encryption.
			 * @param &dg discrete Gaussian generator.
			 * @param &plaintext the plaintext input.
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			void Encrypt(const LPPublicKey<Element> &publicKey, 
				DiscreteGaussianGenerator &dg, 
				const PlaintextEncodingInterface &plaintext, 
				Ciphertext<Element> *ciphertext) const;
			
			/**
			 * Method for decrypting plaintext using Ring-LWE NTRU
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decrypted plaintext returned.
			 */			
			DecodingResult Decrypt(const LPPrivateKey<Element> &privateKey, 
				const Ciphertext<Element> &ciphertext,
				PlaintextEncodingInterface *plaintext) const;
			
			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @param &dgg discrete Gaussian generator.
			 * @return function ran correctly.
			 */
			bool KeyGen(LPPublicKey<Element> &publicKey, 
		        	LPPrivateKey<Element> &privateKey, 
			        DiscreteGaussianGenerator &dgg) const;

	};

} // namespace lbcrypto ends
#endif
