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
 * This code implements the Fan-Vercauteren (FV) homomorphic encryption scheme.
 * The scheme is described at http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf (or alternative Internet source:
 * http://dx.doi.org/10.1007/978-3-642-22792-9_29). Implementation details are provided in
 * {the link to the ACM TISSEC manuscript to be added}.
 */

#ifndef LBCRYPTO_CRYPTO_FV_H
#define LBCRYPTO_CRYPTO_FV_H

//Includes Section
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../math/backend.h"
#include "pubkeylp.h"
#include "ciphertext.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ilelement.h"

#include "rlwe.h"

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
	class LPCryptoParametersFV : public LPCryptoParametersRLWE<Element> {

		public:
			
			/**
			 * Constructor that initializes all values to 0.
			 */
			LPCryptoParametersFV() : LPCryptoParametersRLWE<Element>() {}

			/**
			 * Copy constructor.
			 *
			 */
			LPCryptoParametersFV(const LPCryptoParametersFV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {}

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
			LPCryptoParametersFV(ElemParams *params,
				const BigBinaryInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				const DiscreteGaussianGenerator &dgg,
				int depth = 1)
					: LPCryptoParametersRLWE<Element>(params,
						plaintextModulus,
						distributionParameter,
						assuranceMeasure,
						securityLevel,
						relinWindow,
						dgg,
						depth) {
						m_delta = (params->GetModulus()).DividedBy(plaintextModulus);
					}

			/**
			* Destructor
			*/
			virtual ~LPCryptoParametersFV() {}
			
			//JSON FACILITY
			/**
			* Serialize the object into a Serialized
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @param fileFlag is an object-specific parameter for the serialization
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj, const std::string fileFlag = "") const {
				if( !serObj->IsObject() )
					return false;

				SerialItem cryptoParamsMap(rapidjson::kObjectType);
				if( this->SerializeRLWE(serObj, cryptoParamsMap, fileFlag) == false )
					return false;

				serObj->AddMember("LPCryptoParametersFV", cryptoParamsMap.Move(), serObj->GetAllocator());
				serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersFV", serObj->GetAllocator());

				return true;
			}

			/**
			* Populate the object from the deserialization of the Setialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj) {
				Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersFV");
				if( mIter == serObj.MemberEnd() ) return false;

				return this->DeserializeRLWE(mIter);
			}

			const BigBinaryInteger& GetDelta() const { return m_delta; }

			void SetDelta(const BigBinaryInteger &delta) { m_delta = delta; }
			
			/**
			* == operator to compare to this instance of LPCryptoParametersLTV object. 
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersFV<Element> *el = dynamic_cast<const LPCryptoParametersFV<Element> *>(&rhs);

				if( el == 0 ) return false;

				if(m_delta != el->m_delta) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

		private:
			BigBinaryInteger m_delta;
	};

	/**
	* @brief Public key implementation template for FV-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyFV : public LPPublicKey<Element> {
	public:

		/**
		* Default constructor
		*/
		LPPublicKeyFV() {}

		/**
		* Basic constructor for setting crypto params
		*
		* @param cryptoParams is the reference to cryptoParams
		*/
		LPPublicKeyFV(LPCryptoParameters<Element> &cryptoParams) {
			this->SetCryptoParameters(&cryptoParams);
		}

		/**
		* Copy constructor
		*/
		explicit LPPublicKeyFV(const LPPublicKey<Element> &rhs);

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		LPPublicKeyFV<Element>& operator=(const LPPublicKeyFV<Element> &rhs);

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
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const { return true;  };

		/**
		* Higher level info about the serialization is saved here
		* @param serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized* serObj, const std::string flag) const { return true;  };

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
	* @brief Private key implementation template for FV-based schemes
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPrivateKeyFV : public LPPrivateKey<Element> {
	
	public:
		/**
		* Default constructor
		*/
		LPPrivateKeyFV() {}

		/**
		* Basic constructor for setting crypto params
		*
		* @param cryptoParams is the reference to cryptoParams
		*/
		LPPrivateKeyFV(LPCryptoParameters<Element> &cryptoParams) {
			this->SetCryptoParameters(&cryptoParams);
		}

		/**
		* Copy constructor
		*/
		explicit LPPrivateKeyFV(const LPPrivateKeyLTV<Element> &rhs);

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		LPPrivateKeyFV<Element>& operator=(const LPPrivateKeyFV<Element> &rhs);

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
		// 	const LPCryptoParametersFV<Element> *cryptoParams =
		// 	dynamic_cast<const LPCryptoParametersFV<Element>*>(&this->GetCryptoParameters());

		// 	LPPublicKeyFV<Element> *publicKey =
		// 		dynamic_cast<LPPublicKeyFV<Element>*>(pub);

		// 	const ElemParams &elementParams = cryptoParams->GetElementParams();
		// 	const DiscreteGaussianGenerator &dgg = cryptoParams->GetDiscreteGaussianGenerator();
		// 	const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

		// 	Element e(dgg, elementParams, Format::COEFFICIENT);
		// 	e.SwitchFormat();

		// 	Element b(e);

		// 	// b -= (a*m_sk + e);

		// 	publicKey->SetPublicElements({ b, a });
		// }

		//JSON FACILITY
		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const { return true;  };

		/**
		* Higher level info about the serialization is saved here
		* @param serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized* serObj, const std::string flag) const { return true;  };

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
		LPPrivateKeyFV& operator=(LPPrivateKeyFV &rhs) {
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
	* @brief Evaluation/proxy key implementation template for FV-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyFV : public LPEvalKey<Element> {
	public:

		/**
		* Default constructor
		*/

		LPEvalKeyFV() {}

		/**
		* Basic constructor for setting crypto params
		*
		* @param cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyFV(LPCryptoParameters<Element> &cryptoParams) {
			this->SetCryptoParameters(&cryptoParams);
		}

		/**
		* Get Crypto Parameters.
		* @return the crypto parameters.
		*/
		const LPCryptoParameters<Element> &GetCryptoParameters() const { return *m_cryptoParameters; }

		/**
		* Implementation of the Get accessor for eval key elements (power of base of secret key).
		* @return the private element.
		*/
		const std::vector<Element> &GetEvalKeyElements() const { return m_elements; }

		/**
		* Implementation of the Get accessor for eval key elements (uniformly generated).
		* @return the private element.
		*/
		const std::vector<Element> &GetEvalKeyElementsGenerated() const { return m_elementsGenerated; }

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
		* Implementation of the writeable accessor for eval key elements (power of base for secret key).
		* @return the private element.
		*/
		std::vector<Element> &AccessEvalKeyElements() { return m_elements; }

		/**
		* Implementation of the writeable accessor for eval key elements (uniformly generated).
		* @return the private element.
		*/
		std::vector<Element> &AccessEvalKeyElementsGenerated() { return m_elementsGenerated; }

		/**
		* Sets crypto params.
		*
		* @param *cryptoParams parameters.
		* @return the crypto parameters.
		*/
		void SetCryptoParameters(LPCryptoParameters<Element> *cryptoParams) { m_cryptoParameters = cryptoParams; }

		/*
		* Implementation of the Set accessor for evaluation key elements (power of base of secret key).
		* @private &x the public element.
		*/
		void SetEvalKeyElements(std::vector<Element> &elements) { m_elements = elements; }

		/**
		* Implementation of the Set accessor for evaluation key elements (uniformly generated).
		* @private &x the public element.
		*/
		void SetEvalKeyElementsGenerated(std::vector<Element> &elements) { m_elementsGenerated = elements; }

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
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const {
			return true;
		};

		/**
		* Higher level info about the serialization is saved here
		* @param serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized* serObj, const std::string flag) const {
			return true;
		};

		/**
		* Populate the object from the deserialization of the Setialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj) { return false; }
		bool Deserialize(const Serialized& serObj, const CryptoContext<Element>* ctx) {
			return true;
		};

	private:
		LPCryptoParameters<Element> *m_cryptoParameters;

		//elements used for evaluation key - with power of base of secret key
		std::vector<Element> m_elements;
		//elements with uniform elements
		std::vector<Element> m_elementsGenerated;

		//pointer to public key
		const LPPublicKey<Element> *m_publicKey;

	};


	/**
	* @brief Encryption algorithm implementation template for FV-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmFV : public LPEncryptionAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
	public:

		//inherited constructors
		LPAlgorithmFV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
		LPAlgorithmFV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

		/**
		* Method for encrypting plaintext using FV
		*
		* @param &publicKey public key used for encryption.
		* @param &plaintext the plaintext input.
		* @param *ciphertext ciphertext which results from encryption.
		*/
		EncryptResult Encrypt(const LPPublicKey<Element> &pubKey,
			const Element &plaintext,
			Ciphertext<Element> *ciphertext) const;

		/**
		* Method for decrypting plaintext using FV
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
	* @brief PRE scheme based on BV.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEFV : public LPSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> { //public LPSHEAlgorithm<Element>, 
	public:

		//inherited constructors
		LPAlgorithmSHEFV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
		LPAlgorithmSHEFV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

		/**
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPrivateKey encryption key for the new ciphertext.
		* @param &origPrivateKey original private key used for decryption.
		* @param &ddg discrete Gaussian generator.
		* @param *evalKey the evaluation key.
		*/
		bool RelinKeyGen(const LPPrivateKey<Element> &privateKey,
			LPEvalKey<Element> *evalKey) const;
		
		void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const {}

		void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext, const LPEvalKey<Element> &evalKey) const;

		void EvalAdd(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const;
	};

	/**
	* @brief Main public key encryption scheme for FV implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeFV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeFV() : LPPublicKeyEncryptionScheme<Element>() {}
		LPPublicKeyEncryptionSchemeFV(std::bitset<FEATURESETSIZE> mask);

		//These functions can be implemented later
		//Initialize(mask);

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
