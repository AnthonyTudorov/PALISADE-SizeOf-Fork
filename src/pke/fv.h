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
 * The scheme is described at http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf 
 * (or alternative Internet source:
 * http://dx.doi.org/10.1007/978-3-642-22792-9_29). Implementation details are provided in
 * {the link to the ACM TISSEC manuscript to be added}.
 */

#ifndef LBCRYPTO_CRYPTO_FV_H
#define LBCRYPTO_CRYPTO_FV_H

//Includes Section
#include "../palisade.h"

namespace lbcrypto {

	/**
	 * @brief Crypto parameters class for RLWE-based schemes.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPCryptoParametersFV : public LPCryptoParametersRLWE<Element> {

		public:
			/**
			 * Default constructor.
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
			 * @param delta FV-specific factor that is multiplied by the plaintext polynomial.
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
			
			/**
			* Serialize the object into a Serialized
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj) const {
				if( !serObj->IsObject() )
					return false;

				SerialItem cryptoParamsMap(rapidjson::kObjectType);
				if( this->SerializeRLWE(serObj, cryptoParamsMap) == false )
					return false;

				cryptoParamsMap.AddMember("delta", m_delta.ToString(), serObj->GetAllocator());
				cryptoParamsMap.AddMember("mode", std::to_string(m_mode), serObj->GetAllocator());
				cryptoParamsMap.AddMember("bigmodulus", m_bigModulus.ToString(), serObj->GetAllocator());
				cryptoParamsMap.AddMember("bigrootofunity", m_bigRootOfUnity.ToString(), serObj->GetAllocator());

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

				if( this->DeserializeRLWE(mIter) == false )
					return false;

				SerialItem::ConstMemberIterator pIt;
				if( (pIt = mIter->value.FindMember("delta")) == mIter->value.MemberEnd() )
					return false;
				BigBinaryInteger delta(pIt->value.GetString());

				if( (pIt = mIter->value.FindMember("mode")) == mIter->value.MemberEnd() )
					return false;
				MODE mode = (MODE)atoi(pIt->value.GetString());

				if( (pIt = mIter->value.FindMember("bigmodulus")) == mIter->value.MemberEnd() )
					return false;
				BigBinaryInteger bigmodulus(pIt->value.GetString());

				if( (pIt = mIter->value.FindMember("bigrootofunity")) == mIter->value.MemberEnd() )
					return false;
				BigBinaryInteger bigrootofunity(pIt->value.GetString());

				this->SetBigModulus(bigmodulus);
				this->SetBigRootOfUnity(bigrootofunity);
				this->SetMode(mode);
				this->SetDelta(delta);

				return true;
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
			* Configures the mode for generating the secret key polynomial
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
			// factor delta = floor(q/p) that is multipled by the plaintext polynomial 
			// in FV (most significant bit ranges are used to represent the message)
			BigBinaryInteger m_delta;
			
			// specifies whether the keys are generated from discrete 
			// Gaussian distribution or ternary distribution with the norm of unity
			MODE m_mode;
			
			// larger modulus that is used in polynomial multiplications within EvalMult (before rounding is done)
			BigBinaryInteger m_bigModulus;
			
			// primitive root of unity for m_bigModulus
			BigBinaryInteger m_bigRootOfUnity;
	};

	/**
	* @brief Parameter generation for FV.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmParamsGenFV : public LPParameterGenerationAlgorithm<Element> { 
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmParamsGenFV() {}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		*/
		bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const;

	};

	/**
	* @brief Encryption algorithm implementation for FV
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmFV : public LPEncryptionAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmFV() {}

		/**
		* Method for encrypting plaintext using FV
		*
		* @param publicKey public key used for encryption.
		* @param &plaintext the plaintext input.
		* @return ciphertext which results from encryption.
		*/
		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
			Element &plaintext) const;

		/**
		* Method for decrypting plaintext using FV
		*
		* @param privateKey private key used for decryption.
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
		* @param cc cryptocontext for the keys to be generated.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
		* @return key pair including the private and public key
		*/
		LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse=false) const;
	};

	/**
	* @brief SHE algotithms implementation for FV.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEFV : public LPSHEAlgorithm<Element> { 
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmSHEFV() {}

		/**
		* Function for homomorphic addition of ciphertexts.
		*
		* @param ct1 fist input ciphertext.
		* @param ct2 second input ciphertext.
		* @return new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ct1, 
			const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @return new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ct1, 
			const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Function for evaluating multiplication on ciphertexts.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return resulting EvalMult ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ct1, 
			const shared_ptr<Ciphertext<Element>> ct2) const {
			std::string errMsg = "LPAlgorithmSHEFV::EvalMult without RelinKey is not currently implemented for FV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function for evaluating multiplication on ciphertext followed by key switching operation.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext 
		*  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ct1,
			const shared_ptr<Ciphertext<Element>> ct, const shared_ptr<LPEvalKey<Element>> ek) const;

		/**
		* Method for generating a KeySwitchHint
		*
		* @param originalPrivateKey Original private key used for encryption.
		* @param newPrivateKey New private key to generate the keyswitch hint.
		* @return resulting keySwitchHint.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey, 
			const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {
			std::string errMsg = "LPAlgorithmSHEFV::KeySwitchGen  is not applicable for FV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for key switching based on a KeySwitchHint
		*
		* @param keySwitchHint Hint required to perform the ciphertext switching.
		* @param &cipherText Original ciphertext to perform switching on.
		* @return new ciphertext
		*/
		shared_ptr<Ciphertext<Element>> KeySwitch(const shared_ptr<LPEvalKey<Element>> keySwitchHint, 
			const shared_ptr<Ciphertext<Element>> cipherText) const {
			std::string errMsg = "LPAlgorithmSHEFV::KeySwitch  is not applicable for FV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function to generate 1..log(q) encryptions for each bit of the square of the original private key
		*
		* @param k1 private key.
		* @return evaluation key.
		*/
		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(
					const shared_ptr<LPPrivateKey<Element>> k1) const;
		
		/**
		* Function for evaluating ciphertext at an index; works only with odd indices in the ciphertext
		*
		* @param ciphertext the input ciphertext.
		* @param i index of the item to be "extracted", starts with 2.
		* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
		*/
		shared_ptr<Ciphertext<Element>> EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext, const usint i,
			const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const {
			std::string errMsg = "LPAlgorithmSHEFV::EvalAtIndex  is not implemented for FV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}


		/**
		* Generate automophism keys for a given private key; works only with odd indices in the ciphertext
		*
		* @param publicKey original public key.
		* @param origPrivateKey original private key.
		* @param size number of automorphims to be computed; starting from plaintext index 2; maximum is m/2-1
		* @param *tempPrivateKey used to store permutations of private key; 
		* passed as pointer because instances of LPPrivateKey cannot be created within the method itself
		* @param *evalKeys the evaluation keys; index 0 of the vector corresponds to plaintext index 2, 
		* index 1 to plaintex index 3, etc.
		*/
		bool EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey,
			const usint size, shared_ptr<LPPrivateKey<Element>> *tempPrivateKey,
			std::vector<shared_ptr<LPEvalKey<Element>>> *evalKeys) const {
			std::string errMsg = "LPAlgorithmSHEFV::EvalAutomorphismKeyGen is not implemented for FV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}

	};

	/**
	* @brief Main public key encryption scheme for FV implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeFV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeFV() : LPPublicKeyEncryptionScheme<Element>() {
			this->m_algorithmParamsGen = new LPAlgorithmParamsGenFV<Element>();
		}
		LPPublicKeyEncryptionSchemeFV(std::bitset<FEATURESETSIZE> mask);

		//These functions can be implemented later
		//Initialize(mask);

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
