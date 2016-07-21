/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Nishanth Pasham <np386@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>, Jerry Ryan <gwryan@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 * 
 * Copyright (c) 2015-2016, New Jersey Institute of Technology (NJIT)
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
 * This code implements the Brakerski-Vaikuntanathan (BV) homomorphic encryption scheme.
 * The scheme is described at http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf (or alternative Internet source:
 * http://dx.doi.org/10.1007/978-3-642-22792-9_29). Implementation details are provided in
 * {the link to the ACM TISSEC manuscript to be added}.
 */

#ifndef LBCRYPTO_CRYPTO_BV_H
#define LBCRYPTO_CRYPTO_BV_H

//Includes Section
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../math/backend.h"
#include "pubkeylp.h"
#include "ciphertext.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ilelement.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	/**
	 * @brief Crypto parameters class for RLWE-based schemes.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPCryptoParametersRLWE : public LPCryptoParametersImpl<Element> {
		public:
			
			/**
			 * Constructor that initializes all values to 0.
			 */
			LPCryptoParametersRLWE() : LPCryptoParametersImpl<Element>() {
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
			 * Copy constructor.
			 *
			 */
			LPCryptoParametersRLWE(const LPCryptoParametersRLWE &rhs) : LPCryptoParametersImpl<Element>(NULL, rhs.GetPlaintextModulus()) {

				m_distributionParameter = rhs.m_distributionParameter;
				m_assuranceMeasure = rhs.m_assuranceMeasure;
				m_securityLevel = rhs.m_securityLevel;
				m_relinWindow = rhs.m_relinWindow;
				m_dgg = rhs.m_dgg;
				m_depth = rhs.m_depth;
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
			LPCryptoParametersRLWE(ElemParams *params,
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
			virtual ~LPCryptoParametersRLWE() {
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
			bool Serialize(Serialized* serObj, const std::string fileFlag = "") const {};

			/**
			* Populate the object from the deserialization of the Setialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj) {};
			
			
			/**
			* == operator to compare to this instance of LPCryptoParametersLTV object. 
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersRLWE<Element> &el = dynamic_cast<const LPCryptoParametersRLWE<Element> &>(rhs);

				return  this->GetPlaintextModulus() == el.GetPlaintextModulus() &&
						this->GetElementParams() == el.GetElementParams() &&
						m_distributionParameter == el.GetDistributionParameter() &&
						m_assuranceMeasure == el.GetAssuranceMeasure() &&
						m_securityLevel == el.GetSecurityLevel() &&
						m_relinWindow == el.GetRelinWindow();
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
	* @brief Public key implementation template for BV-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyBV : public LPPublicKey<Element> {
	public:

		/**
		* Default constructor
		*/
		LPPublicKeyBV() {}

		/**
		* Basic constructor for setting crypto params
		*
		* @param cryptoParams is the reference to cryptoParams
		*/
		LPPublicKeyBV(LPCryptoParameters<Element> &cryptoParams) {
			this->SetCryptoParameters(&cryptoParams);
		}

		/**
		* Copy constructor
		*/
		explicit LPPublicKeyBV(const LPPublicKey<Element> &rhs);

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		LPPublicKeyBV<Element>& operator=(const LPPublicKeyBV<Element> &rhs);

		/**
		* Get Crypto Parameters.
		* @return the crypto parameters.
		*/
		const LPCryptoParameters<Element> &GetCryptoParameters() const { return *m_cryptoParameters; }

		/**
		* Implementation of the Get accessor for public element.
		* @return the public element.
		*/
		const Element & GetPublicElement() const { return m_a; }

		/**
		* Implementation of the Get accessor for generated public element b = a s + p e.
		* @return the public element.
		*/
		const Element & GetGeneratedPublicElement() const { return m_b; }

		/**
		* Implementation of the Get accessor for generated public element b = a s + p e.
		* @return the public elements.
		*/
		const std::vector<Element> & GetPublicElements() const { return { m_a, m_b }; }

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
		void SetPublicElement(const Element &x) { m_a = x; }

		/**
		* Implementation of the Set accessor for generated element.
		* @private &x the generated element.
		*/
		void SetGeneratedPublicElement(const Element &x) {m_b = x;}

		/**
		* Implementation of the Set accessor for both public elements.
		* @private &x the generated element.
		*/
		void SetPublicElements(const std::vector<Element> &vector) { 
			m_a = vector[0];
			m_b = vector[1];
		}

		//JSON FACILITY
		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const {};

		/**
		* Higher level info about the serialization is saved here
		* @param serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized* serObj, const std::string flag) const {};

		/**
		* Populate the object from the deserialization of the Setialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj) { return false; }
		bool Deserialize(const Serialized& serObj, const CryptoContext<Element>* ctx) {};

	private:
		LPCryptoParameters<Element> *m_cryptoParameters;

		//polynomials used as the public key
		//Elements (a, b = a s + p e);
		Element m_a;
		Element m_b;
	};

	/**
	* @brief Private key implementation template for BV-based schemes
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPrivateKeyBV : public LPPrivateKey<Element> {
	public:

		/**
		* Default constructor
		*/

		LPPrivateKeyBV() {}

		/**
		* Basic constructor for setting crypto params
		*
		* @param cryptoParams is the reference to cryptoParams
		*/

		LPPrivateKeyBV(LPCryptoParameters<Element> &cryptoParams) {
			this->SetCryptoParameters(&cryptoParams);
		}

		/**
		* Copy constructor
		*/
		explicit LPPrivateKeyBV(const LPPrivateKeyLTV<Element> &rhs);

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		LPPrivateKeyBV<Element>& operator=(const LPPrivateKeyBV<Element> &rhs);

		/**
		* Get Crypto Parameters.
		* @return the crypto parameters.
		*/
		const LPCryptoParameters<Element> &GetCryptoParameters() const { return *m_cryptoParameters; }

		/**
		* Implementation of the Get accessor for private element.
		* @return the private element.
		*/
		const Element & GetPrivateElement() const { return m_sk; }

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
		void SetPrivateElement(const Element &x) { m_sk = x; }

		/**
		* Implements the procedure to set the public key
		* The formula is (a, b = a s + p e)
		*
		* @param a Uniformly distributed polynomial
		* @param &pub a public key.
		*/
		void MakePublicKey(const Element &a, LPPublicKey<Element> *pub) const;

		//JSON FACILITY
		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const {};

		/**
		* Higher level info about the serialization is saved here
		* @param serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized* serObj, const std::string flag) const {};

		/**
		* Populate the object from the deserialization of the Setialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj) { return false; }
		bool Deserialize(const Serialized& serObj, const CryptoContext<Element>* ctx) {};

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		LPPrivateKeyBV& operator=(LPPrivateKeyBV &rhs) {
			*m_cryptoParameters = *rhs.m_cryptoParameters;
			m_sk = rhs.m_sk;

			return *this;
		}


	private:
		LPCryptoParameters<Element> *m_cryptoParameters;
		//private key polynomial
		Element m_sk;

	};

	/**
	* @brief Encryption algorithm implementation template for BV-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmBV : public LPEncryptionAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
	public:

		//inherited constructors
		LPAlgorithmBV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
		LPAlgorithmBV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

		/**
		* Method for encrypting plaintext using BV
		*
		* @param &publicKey public key used for encryption.
		* @param &plaintext the plaintext input.
		* @param *ciphertext ciphertext which results from encryption.
		*/
		EncryptResult Encrypt(const LPPublicKey<Element> &publicKey,
			const Element &plaintext,
			Ciphertext<Element> *ciphertext) const;

		/**
		* Method for decrypting plaintext using BV
		*
		* @param &privateKey private key used for decryption.
		* @param &ciphertext ciphertext id decrypted.
		* @param *plaintext the plaintext output.
		* @return the decrypted plaintext returned.
		*/
		DecryptResult Decrypt(const LPPrivateKey<Element> &privateKey,
			const Ciphertext<Element> &ciphertext,
			Element *plaintext) const;

		/**
		* Function to generate public and private keys
		*
		* @param &publicKey private key used for decryption.
		* @param &privateKey private key used for decryption.
		* @return function ran correctly.
		*/
		virtual bool KeyGen(LPPublicKey<Element> *publicKey,
			LPPrivateKey<Element> *privateKey) const;
	};

	/**
	* @brief Main public key encryption scheme for BV implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeBV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeBV(size_t chunksize) : LPPublicKeyEncryptionScheme<Element>(chunksize) {}
		LPPublicKeyEncryptionSchemeBV(std::bitset<FEATURESETSIZE> mask, size_t chunksize);

		//These functions can be implemented later
		//Initialize(mask);

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
