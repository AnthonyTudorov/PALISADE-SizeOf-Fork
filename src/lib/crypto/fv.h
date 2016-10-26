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
#include "../palisade.h"

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
			LPCryptoParametersFV() : LPCryptoParametersRLWE<Element>() {
				m_delta = BigBinaryInteger::ZERO;
				m_mode = RLWE;
				m_bigModulus = BigBinaryInteger::ZERO;
				m_bigRootOfUnity = BigBinaryInteger::ZERO;
			}

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
			 * @param dgg discrete Gaussian generator instance
			 * @param mode optimization setting (RLWE vs OPTIMIZED)
			 * @param bigModulus modulus used in polynomial multiplications in EvalMult
			 * @param bigRootOfUnity root of unity for bigModulus
			 * @param depth depth which is set to 1.
			 */
			LPCryptoParametersFV(shared_ptr<ElemParams> params,
				const BigBinaryInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				const DiscreteGaussianGenerator &dgg,
				const BigBinaryInteger &delta,
				MODE mode,
				const BigBinaryInteger &bigModulus,
				const BigBinaryInteger &bigRootOfUnity,
				int depth = 1)
					: LPCryptoParametersRLWE<Element>(params,
						plaintextModulus,
						distributionParameter,
						assuranceMeasure,
						securityLevel,
						relinWindow,
						dgg,
						depth) {
						m_delta = delta;
						m_mode = mode;
						m_bigModulus = bigModulus;
						m_bigRootOfUnity = bigRootOfUnity;
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

			/**
			* Gets the value of the delta factor.
			*
			* @return the delta factor.
			*/
			const BigBinaryInteger& GetDelta() const { return m_delta; }

			/**
			* Gets the mode setting: RLWE or OPTIMIZED.
			*
			* @return the mode setting.
			*/
			MODE GetMode() const { return m_mode; }

			/**
			* Gets the modulus used for polynomial multiplications in EvalMult
			*
			* @return the modulus value.
			*/
			const BigBinaryInteger& GetBigModulus() const { return m_bigModulus; }

			/**
			* Gets the primitive root of unity used for polynomial multiplications in EvalMult
			*
			* @return the primitive root of unity value.
			*/
			const BigBinaryInteger& GetBigRootOfUnity() const { return m_bigRootOfUnity; }

			/**
			* Sets the value of the delta factor
			*/
			void SetDelta(const BigBinaryInteger &delta) { m_delta = delta; }

			/**
			* Configures the mode
			*/
			void SetMode(MODE mode) { m_mode = mode; }

			/**
			* Sets the modulus used for polynomial multiplications in EvalMult
			*/
			void SetBigModulus(const BigBinaryInteger &bigModulus) { m_bigModulus = bigModulus; }

			/**
			* Sets primitive root of unity used for polynomial multiplications in EvalMult
			*/
			void SetBigRootOfUnity(const BigBinaryInteger &bigRootOfUnity) { m_bigRootOfUnity = bigRootOfUnity; }

			/**
			* == operator to compare to this instance of LPCryptoParametersFV object. 
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersFV<Element> *el = dynamic_cast<const LPCryptoParametersFV<Element> *>(&rhs);

				if( el == 0 ) return false;

				if (m_delta != el->m_delta) return false;
				if (m_mode != el->m_mode) return false;
				if (m_bigModulus != el->m_bigModulus) return false;
				if (m_bigRootOfUnity != el->m_bigRootOfUnity) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

		private:
			//factor delta = floor(q/p) that is multipled by the plaintext polynomial in FV (most significant bit ranges are used to represent the message)
			BigBinaryInteger m_delta;
			
			//specifies whether the keys are generated from discrete Gaussian distribution or ternary distribution with the norm of unity
			MODE m_mode;
			
			//larger modulus that is used in polynomial multiplications within EvalMult (before rounding is done)
			BigBinaryInteger m_bigModulus;
			
			//primitive root of unity for m_bigModulus
			BigBinaryInteger m_bigRootOfUnity;
	};

	/**
	* @brief Parameter generation for FV.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmParamsGenFV : public LPParameterGenerationAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> { //public LPSHEAlgorithm<Element>, 
	public:

		//inherited constructors
		LPAlgorithmParamsGenFV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
		LPAlgorithmParamsGenFV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param *cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		*/
		bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const;

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
		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
			Element &plaintext) const;

		/**
		* Method for decrypting plaintext using FV
		*
		* @param &privateKey private key used for decryption.
		* @param &ciphertext ciphertext id decrypted.
		* @param *plaintext the plaintext output.
		* @return the decrypted plaintext returned.
		*/
		DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const shared_ptr<Ciphertext<Element>> ciphertext,
			Element *plaintext) const;

		/**
		* Function to generate public and private keys
		*
		* @param &publicKey private key used for decryption.
		* @param &privateKey private key used for decryption.
		* @return function ran correctly.
		*/
		LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc) const;
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
		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(
					const shared_ptr<LPPrivateKey<Element>> k1,
					const shared_ptr<LPPrivateKey<Element>> k2) const;
		
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2) const {
					std::string errMsg = "LPAlgorithmSHEFV::EvalMult without RelinKey is not applicable for FV SHE Scheme.";
					throw std::runtime_error(errMsg);
		}

		/**
		* Function for homomorphic addition of ciphertexts.
		*
		* @param &ciphertext1 the input ciphertext.
		* @param &ciphertext2 the input ciphertext.
		* @param *newCiphertext the new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		*
		* @param &ciphertext1 the input ciphertext.
		* @param &ciphertext2 the input ciphertext.
		* @param *newCiphertext the new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Function for evaluating multiplication on ciphertext followed by key switching operation.
		*
		* @param &ciphertext1 first input ciphertext.
		* @param &ciphertext2 second input ciphertext.
		* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ct1,
				const shared_ptr<Ciphertext<Element>> ct, const shared_ptr<LPEvalKey<Element>> ek) const;
	};

	/**
	* @brief Main public key encryption scheme for FV implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeFV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeFV() : LPPublicKeyEncryptionScheme<Element>() {
			this->m_algorithmParamsGen = new LPAlgorithmParamsGenFV<Element>(*this);
		}
		LPPublicKeyEncryptionSchemeFV(std::bitset<FEATURESETSIZE> mask);

		//These functions can be implemented later
		//Initialize(mask);

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
