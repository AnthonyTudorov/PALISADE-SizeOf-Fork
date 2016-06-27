/**0
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Nishanth Pasham <np386@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>, Jerry Ryan <gwryan@njit.edu>
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
#include "lweahe.h"
#include "lwepre.h"
#include "lweshe.h"
#include "lwefhe.h"
#include "lweautomorph.h"
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
	class LPCryptoParametersLTV : public LPCryptoParametersImpl<Element> {
		public:
			
			/**
			 * Constructor that initializes all values to 0.
			 */
			LPCryptoParametersLTV() : LPCryptoParametersImpl<Element>() {
				//m_params = new ElementParams();commented out by Gyana
				//m_plaintextModulus = new BigBinaryInteger();commented out by Gyana 
				m_distributionParameter = 0.0f;
				m_assuranceMeasure = 0.0f;
				m_securityLevel = 0.0f;
				m_relinWindow = 1;
				m_dgg = DiscreteGaussianGenerator();
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
			LPCryptoParametersLTV(ElemParams *params,
				const BigBinaryInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				const DiscreteGaussianGenerator &dgg,
				int depth = 1) : LPCryptoParametersImpl<Element>(params,plaintextModulus)
			{
				m_distributionParameter = distributionParameter;
				m_assuranceMeasure = assuranceMeasure;
				m_securityLevel = securityLevel;
				m_relinWindow = relinWindow;
				m_dgg = dgg;
				m_depth = depth;
			}

			/**
			* Destructor
			*/
			virtual ~LPCryptoParametersLTV() {}
			
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
			void Initialize(ElemParams *params,
				const BigBinaryInteger &plaintextModulus,  
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				const DiscreteGaussianGenerator &dgg,
				int depth = 1)
			{
				this->SetElementParams(params);
				this->SetPlaintextModulus(plaintextModulus);
				m_distributionParameter = distributionParameter;
				m_assuranceMeasure = assuranceMeasure;
				m_securityLevel = securityLevel;
				m_relinWindow = relinWindow;
				m_dgg = dgg;
				m_depth = depth;
			}
			
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
			 * Returns reference to Discrete Gaussian Generator
			 *
			 * @return reference to Discrete Gaussian Generaror.
			 */
			const DiscreteGaussianGenerator &GetDiscreteGaussianGenerator() const {return m_dgg;}

			//@Set Properties
			
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
			 * Sets the discrete Gaussian Generator
			 */
			void SetDiscreteGaussianGenerator(const DiscreteGaussianGenerator &dgg) {m_dgg = dgg;}

			//JSON FACILITY
			/**
			* Serialize the object into a Serialized
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @param fileFlag is an object-specific parameter for the serialization
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj, const std::string fileFlag = "") const;

			/**
			* Populate the object from the deserialization of the Setialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj);

			bool operator==(const LPCryptoParameters<Element>* cmp) const {
				const LPCryptoParametersLTV<Element> *el = dynamic_cast<const LPCryptoParametersLTV<Element> *>(cmp);

				if( cmp == 0 ) return false;

				return  this->GetPlaintextModulus() == cmp->GetPlaintextModulus() &&
						this->GetElementParams() == &cmp->GetElementParams() &&
						m_distributionParameter == el->GetDistributionParameter() &&
						m_assuranceMeasure == el->GetAssuranceMeasure() &&
						m_securityLevel == el->GetSecurityLevel() &&
						m_relinWindow == el->GetRelinWindow();
			}

		private:
			//standard deviation in Discrete Gaussian Distribution
			float m_distributionParameter;
			//assurance measure alpha
			float m_assuranceMeasure;
			//root Hermite value /delta
			float m_securityLevel;
			//relinearization window
			usint m_relinWindow;
			//depth of computations; used for FHE
			int m_depth;
			//Discrete Gaussian Generator
			DiscreteGaussianGenerator m_dgg;
	};

	/**
	 * @brief Template for Stehle-Stenfeld crypto parameters.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPCryptoParametersStehleSteinfeld : public LPCryptoParametersLTV<Element> {
	public:
			/**
			 * Default constructor that initializes all values to 0.
			 */
			LPCryptoParametersStehleSteinfeld() : LPCryptoParametersLTV<Element>() {
				m_distributionParameterStSt = 0.0f;
				m_dggStSt = DiscreteGaussianGenerator();
			}

			/**
			 * Returns the value of standard deviation r for discrete Gaussian distribution used in Key Generation
			 *
			 * @return the standard deviation r.
			 */
			float GetDistributionParameterStSt() const {return m_distributionParameterStSt;}

			/**
			 * Returns reference to Discrete Gaussian Generator for keys
			 *
			 * @return reference to Discrete Gaussian Generaror.
			 */
			const DiscreteGaussianGenerator &GetDiscreteGaussianGeneratorStSt() const {return m_dggStSt;}

			//@Set Properties
			
			/**
			 * Sets the value of standard deviation r for discrete Gaussian distribution
			 */
			void SetDistributionParameterStSt(float distributionParameterStSt) {m_distributionParameterStSt = distributionParameterStSt;}

			/**
			 * Sets the discrete Gaussian Generator for keys
			 */
			void SetDiscreteGaussianGeneratorStSt(const DiscreteGaussianGenerator &dggStSt) {m_dggStSt = dggStSt;}

			/**
			* Serialize the object into a Serialized
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @param fileFlag is an object-specific parameter for the serialization
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj, const std::string fileFlag = "") const;

			/**
			* Populate the object from the deserialization of the Setialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj);


			bool operator==(const LPCryptoParameters<Element>* cmp) const {
				const LPCryptoParametersStehleSteinfeld<Element> *el = dynamic_cast<const LPCryptoParametersStehleSteinfeld<Element> *>(cmp);

				if( cmp == 0 ) return false;

				return  this->GetPlaintextModulus() == cmp->GetPlaintextModulus() &&
						this->GetElementParams() == &cmp->GetElementParams() &&
						this->GetDistributionParameter() == el->GetDistributionParameter() &&
						this->GetAssuranceMeasure() == el->GetAssuranceMeasure() &&
						this->GetSecurityLevel() == el->GetSecurityLevel() &&
						this->GetRelinWindow() == el->GetRelinWindow() &&
						m_distributionParameterStSt == el->GetDistributionParameterStSt();
			}

		private:
			//standard deviation in Discrete Gaussian Distribution used for Key Generation
			float m_distributionParameterStSt;
			//Discrete Gaussian Generator for Key Generation
			DiscreteGaussianGenerator m_dggStSt;
	};

	/* this function is used to deserialize the Crypto Parameters
	 *
	 * @return the parameters or null on failure
	 */
	template <typename Element>
	inline LPCryptoParameters<Element>* DeserializeCryptoParameters(const Serialized& serObj)
	{
		LPCryptoParameters<Element>* parmPtr = 0;

		Serialized::ConstMemberIterator it = serObj.FindMember("LPCryptoParametersType");
		if( it == serObj.MemberEnd() ) return 0;
		std::string type = it->value.GetString();

		if( type == "LPCryptoParametersLTV" ) {
			parmPtr = new LPCryptoParametersLTV<Element>();
		} else if( type == "LPCryptoParametersStehleSteinfeld" ) {
			parmPtr = new LPCryptoParametersStehleSteinfeld<Element>();
		} else
			return 0;

		if( !parmPtr->Deserialize(serObj) ) {
			delete parmPtr;
			return 0;
		}

		return parmPtr;
	}

	/* this function is used to deserialize the Crypto Parameters, to compare them to the existing parameters,
	 * and to fail if they do not match
	 *
	 * @return the parameters or null on failure
	 */
	template <typename Element>
	inline LPCryptoParameters<Element>* DeserializeAndValidateCryptoParameters(const Serialized& serObj, const LPCryptoParameters<Element>& curP)
	{
		LPCryptoParameters<Element>* parmPtr = DeserializeCryptoParameters<Element>(serObj);

		if( parmPtr == 0 ) return 0;

		// make sure the deserialized parms match the ones in the current context
		if( *parmPtr == &curP )
			return parmPtr;

		delete parmPtr;
		return 0;
	}

	/**
	 * @brief Public key implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyLTV : public LPPublicKey<Element>{
		public:

			/**
			* Default constructor
			*/

			LPPublicKeyLTV() {}

			/**
			* Basic constructor for setting crypto params
			*
			* @param cryptoParams is the reference to cryptoParams
			*/
			LPPublicKeyLTV(LPCryptoParameters<Element> &cryptoParams) {
				this->SetCryptoParameters(&cryptoParams);
			}

			/**
			 * Get Crypto Parameters.
			 * @return the crypto parameters.
			 */
			const LPCryptoParameters<Element> &GetCryptoParameters() const {return *m_cryptoParameters;}

			/**
			 * Implementation of the Get accessor for public element.
			 * @return the private element.
			 */
			const Element & GetPublicElement() const {return m_h;}

			/**
			 * Implementation of the Get accessor for auxiliary polynomial used together with the public element.
			 * @return the generated element.
			 */
			//const Element & GetGeneratedElement() const {return m_g;}

			/**
			* Gets writable instance of cryptoparams.
			* @return the crypto parameters.
			*/
			LPCryptoParameters<Element> &AccessCryptoParameters() { return *m_cryptoParameters; }

			/**
			 * Sets crypto params.
			 *
			 * @param *cryptoParams parameters.
			 * @return the crypto parameters.
			 */
			void SetCryptoParameters(LPCryptoParameters<Element> *cryptoParams) { m_cryptoParameters = cryptoParams; }
			
			/**
			 * Implementation of the Set accessor for public element.
			 * @private &x the public element.
			 */
			void SetPublicElement(const Element &x) {m_h = x;}

			/**
			 * Implementation of the Set accessor for generated element.
			 * @private &x the generated element.
			 */
			//void SetGeneratedElement(const Element &x) {m_g = x;}

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
			bool Deserialize(const Serialized& serObj) { return false; }
			bool Deserialize(const Serialized& serObj, const CryptoContext<Element>* ctx);

		private:
			LPCryptoParameters<Element> *m_cryptoParameters;
			//polynomials used for public key
			//Element m_g;
			Element m_h;
	};

	/**
	* @brief Evaluation/proxy key implementation template for Ring-LWE NTRU-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyLTV : public LPEvalKey<Element>{
	public:

		/**
		* Default constructor
		*/

		LPEvalKeyLTV() {}

		/**
		* Basic constructor for setting crypto params
		*
		* @param cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyLTV(LPCryptoParameters<Element> &cryptoParams) {
			this->SetCryptoParameters(&cryptoParams);
		}

		/**
			* Get Crypto Parameters.
			* @return the crypto parameters.
			*/
		const LPCryptoParameters<Element> &GetCryptoParameters() const {return *m_cryptoParameters;}

		/**
		* Implementation of the Get accessor for eval key elements.
		* @return the private element.
		*/
		const std::vector<Element> &GetEvalKeyElements() const { return m_elements; }

		/**
		* Implementation of the Get accessor for public key.
		* @return the public.
		*/
		const LPPublicKey<Element> &GetPublicKey() const { return *m_publicKey; }

		/**
		* Gets writable instance of cryptoparams.
		* @return the crypto parameters.
		*/
		LPCryptoParameters<Element> &AccessCryptoParameters() { return *m_cryptoParameters; }

		/**
		* Implementation of the writeable accessor for eval key elements.
		* @return the private element.
		*/
		std::vector<Element> &AccessEvalKeyElements() { return m_elements; }

		/**
			* Sets crypto params.
			*
			* @param *cryptoParams parameters.
			* @return the crypto parameters.
			*/
		void SetCryptoParameters(LPCryptoParameters<Element> *cryptoParams) { m_cryptoParameters = cryptoParams; }

		/**
		* Implementation of the Set accessor for evaluation key elements.
		* @private &x the public element.
		*/
		void SetEvalKeyElements(std::vector<Element> &elements) { m_elements = elements; }

		/**
		* Implementation of the Set accessor for public key.
		* @private &publicKey the public element.
		*/
		void SetPublicKey(const LPPublicKey<Element> &publicKey) { m_publicKey = &publicKey; }

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
		bool Deserialize(const Serialized& serObj) { return false; }
		bool Deserialize(const Serialized& serObj, const CryptoContext<Element>* ctx);
		
	private:
		LPCryptoParameters<Element> *m_cryptoParameters;
		//elements used for evaluation key
		std::vector<Element> m_elements;

		//pointer to public key
		const LPPublicKey<Element> *m_publicKey;

	};

	//! Implementation class for key switch hint
	/**
	 * @brief Implementation class for key switch hints
	 * @tparam Element a ring element
	 */
	template <class Element>
	class LPKeySwitchHintLTV: public LPKeySwitchHint<Element> {
		public:

			/**
			* Constructor that initializes nothing.
			*/
			LPKeySwitchHintLTV() {
				/*m_sk = NULL;*/
				//m_cryptoParameters;
			}

			LPKeySwitchHintLTV(const LPKeySwitchHintLTV &rhs){
				this->m_sk = rhs.m_sk;
				*this->m_cryptoParameters = *rhs.m_cryptoParameters;
			}


		/**
			* Get Crypto Parameters.
			* @return the crypto parameters.
			*/
		const LPCryptoParameters<Element> &GetCryptoParameters() const {return *m_cryptoParameters;}

		/**
			* Implementation of the Get accessor for private element.
			* @return the private element.
			*/
		const Element & GetHintElement() const {return m_sk;}


		/**
		* Gets writable instance of cryptoparams.
		* @return the crypto parameters.
		*/
		LPCryptoParameters<Element> &AccessCryptoParameters() { return *m_cryptoParameters; }

		/**
			* Sets crypto params.
			*
			* @param *cryptoParams parameters.
			* @return the crypto parameters.
			*/
		void SetCryptoParameters(LPCryptoParameters<Element> *cryptoParams) { m_cryptoParameters = cryptoParams; }

		/**
			* Implementation of the Set accessor for private element.
			* @private &x the private element.
			*/
		void SetHintElement(const Element &x) {m_sk = x;}

			// JSON FACILITY - SetIdFlag Operation
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {
		//	std::unordered_map <std::string, std::string> serializationMap;
			return serializationMap;
		}

		// JSON FACILITY - Serialize Operation
		// TODO - GERARD RYAN
		bool  Serialize(Serialized* serObj, const std::string fileFlag = "") const {
			
			return true;
		}

		// JSON FACILITY - Deserialize Operation
		// TODO - GERARD RYAN
		bool Deserialize(const Serialized& serObj) {	
			return false;
		}

		

		private:
			LPCryptoParameters<Element> *m_cryptoParameters;
			//private key polynomial
			Element m_sk;
	};


	/**
	 * @brief Private key implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPrivateKeyLTV : public LPPrivateKey<Element>{
		public:

			/**
			* Default constructor
			*/

			LPPrivateKeyLTV() {}

			/**
			* Basic constructor for setting crypto params
			*
			* @param cryptoParams is the reference to cryptoParams
			*/

			LPPrivateKeyLTV(LPCryptoParameters<Element> &cryptoParams) {
				this->SetCryptoParameters(&cryptoParams);
			}

			/**
			 * Get Crypto Parameters.
			 * @return the crypto parameters.
			 */
			const LPCryptoParameters<Element> &GetCryptoParameters() const {return *m_cryptoParameters;}

			/**
			 * Implementation of the Get accessor for private element.
			 * @return the private element.
			 */
			const Element & GetPrivateElement() const {return m_sk;}
			
			/**
			 * Implementation of the Get accessor for auxiliary polynomial used along with the private element.
			 * @return the private error element.
			 */
			//const Element & GetPrivateErrorElement() const {return m_e;}

			/**
			* Gets writable instance of cryptoparams.
			* @return the crypto parameters.
			*/
			LPCryptoParameters<Element> &AccessCryptoParameters() { return *m_cryptoParameters; }

			/**
			 * Sets crypto params.
			 *
			 * @param *cryptoParams parameters.
			 * @return the crypto parameters.
			 */
			void SetCryptoParameters(LPCryptoParameters<Element> *cryptoParams) { m_cryptoParameters = cryptoParams; }

			/**
			 * Implementation of the Set accessor for private element.
			 * @private &x the private element.
			 */
			void SetPrivateElement(const Element &x) {m_sk = x;}

			/**
			 * Implementation of the Set accessor for auxiliary polynomial used along with the private element.
			 * @private &x the private error element.
			 */
			//void SetPrivateErrorElement(const Element &x) {m_e = x;}


			/**
			 * Implements the procedure to compute the public key using the current private key
			 * The formula is h = p*g*f^(-1) using standard NTRU notation
			 *
			 * @param g a Gaussian polynomial
			 * @param &pub a public key.
			 */
			void MakePublicKey(const Element &g, LPPublicKey<Element> *pub) const
			{
				pub->SetPublicElement(this->GetCryptoParameters().GetPlaintextModulus()*g*this->GetPrivateElement().MultiplicativeInverse());
			}

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
			bool Deserialize(const Serialized& serObj) { return false; }
			bool Deserialize(const Serialized& serObj, const CryptoContext<Element>* ctx);

			/**
			* Assignment Operator.
			*
			* @param &rhs the copied vector.
			* @return the resulting vector.
			*/
			LPPrivateKeyLTV& operator=(LPPrivateKeyLTV &rhs);
				

	private:
			LPCryptoParameters<Element> *m_cryptoParameters;
			//private key polynomial
			Element m_sk;
			//error polynomial
			//Element m_e;

			
	};

	/**
	 * @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAlgorithmLTV : public LPEncryptionAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
		public:

			//inherited constructors
			LPAlgorithmLTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
			LPAlgorithmLTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

			/**
			 * Method for encrypting plaintext using Ring-LWE NTRU
			 *
			 * @param &publicKey public key used for encryption.
			 * @param &plaintext the plaintext input.
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			void Encrypt(const LPPublicKey<Element> &publicKey, 
				const PlaintextEncodingInterface &plaintext, 
				Ciphertext<Element> *ciphertext) const;

			/**
			 * Method for encrypting numeric values using Ring-LWE NTRU
			 *
			 * @param &publicKey public key used for encryption.
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			void Encrypt(const LPPublicKey<Element> &publicKey, 
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
			 * @return function ran correctly.
			 */
			virtual bool KeyGen(LPPublicKey<Element> *publicKey, 
		        	LPPrivateKey<Element> *privateKey) const;

			/**
			 * Function to generate sparse public and private keys. By sparse it is meant that all even indices are non-zero
			 * and odd indices are set to zero.
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @param &dgg discrete Gaussian generator.
			 * @return function ran correctly.
			 */
			bool SparseKeyGen(LPPublicKey<Element> &publicKey, 
		        	LPPrivateKey<Element> &privateKey, 
			        const DiscreteGaussianGenerator &dgg) const;

	 };

	/**
	 * @brief Concrete feature class for Leveled SHELTV operations
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPLeveledSHEAlgorithmLTV : public LPLeveledSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
		public:	
			//inherited constructors
			LPLeveledSHEAlgorithmLTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
			/**
			 * Constructor 
			 *
			 * @param &scheme is a pointer to the instantiation of the specfic encryption scheme used. 
			 */
			LPLeveledSHEAlgorithmLTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

			/**
			 * Method for generating a KeySwitchHint
			 *
			 * @param &originalPrivateKey Original private key used for encryption.
			 * @param &newPrivateKey New private key to generate the keyswitch hint.
			 * @param *KeySwitchHint is where the resulting keySwitchHint will be placed.
			 */
			virtual void KeySwitchHintGen(const LPPrivateKey<Element> &originalPrivateKey, 
				const LPPrivateKey<Element> &newPrivateKey, LPKeySwitchHint<Element> *keySwitchHint) const ;
			/**
			 * Method for KeySwitching based on a KeySwitchHint
			 *
			 * @param &keySwitchHint Hint required to perform the ciphertext switching.
			 * @param &cipherText Original ciphertext to perform switching on.
			 */
			virtual Ciphertext<Element> KeySwitch(const LPKeySwitchHint<Element> &keySwitchHint,const  Ciphertext<Element> &cipherText) const;

			virtual void QuadraticKeySwitchHintGen(const LPPrivateKey<Element> &originalPrivateKey, const LPPrivateKey<Element> &newPrivateKey, LPKeySwitchHint<Element> *quadraticKeySwitchHint) const;
			
			/**
			 * Method for ModReducing CipherText and the Private Key used for encryption.
			 *
			 * @param *cipherText Ciphertext to perform and apply modreduce on.
			 * @param *privateKey Private key to peform and apply modreduce on.
			 */
			virtual void ModReduce(Ciphertext<Element> *cipherText, LPPrivateKey<Element> *privateKey) const; 
			/**
			 * Method for RingReducing CipherText and the Private Key used for encryption.
			 *
			 * @param *cipherText Ciphertext to perform and apply ringreduce on.
			 * @param *privateKey Private key to peform and apply ringreduce on.
			 */
			virtual void RingReduce(Ciphertext<Element> *cipherText, const LPKeySwitchHint<Element> &keySwitchHint) const ; 
	};

	/**
	 * @brief Encryption algorithm implementation template for Stehle-Stenfeld scheme,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPEncryptionAlgorithmStehleSteinfeld : public LPAlgorithmLTV<Element> {
		public:

			//inherited constructors
			LPEncryptionAlgorithmStehleSteinfeld() : LPAlgorithmLTV<Element>(){};
			LPEncryptionAlgorithmStehleSteinfeld(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPAlgorithmLTV<Element>(scheme) {};
			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @return function ran correctly.
			 */
			 bool KeyGen(LPPublicKey<Element> *publicKey, 
		        	LPPrivateKey<Element> *privateKey) const;
	};

	/**
	 * @brief Main public key encryption scheme for LTV implementation,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyEncryptionSchemeLTV : public LPPublicKeyEncryptionScheme<Element>{
		public:
			LPPublicKeyEncryptionSchemeLTV();
			LPPublicKeyEncryptionSchemeLTV(std::bitset<FEATURESETSIZE> mask);

			virtual ~LPPublicKeyEncryptionSchemeLTV();
			//These functions can be implemented later
			//Initialize(mask);

			void Enable(PKESchemeFeature feature);
	};

	/**
	 * @brief Main public key encryption scheme for Stehle-Stenfeld scheme implementation,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyEncryptionSchemeStehleSteinfeld : public LPPublicKeyEncryptionSchemeLTV<Element>{
		public:
			LPPublicKeyEncryptionSchemeStehleSteinfeld() : LPPublicKeyEncryptionSchemeLTV<Element>() {};
			LPPublicKeyEncryptionSchemeStehleSteinfeld(std::bitset<FEATURESETSIZE> mask);

			void Enable(PKESchemeFeature feature);
	};
} // namespace lbcrypto ends
#endif
