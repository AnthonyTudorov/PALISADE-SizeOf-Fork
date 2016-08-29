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
		bool RelinKeyGen(const LPPrivateKey<Element> &privateKey, LPEvalKey<Element> *ek) const;
		
		void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const {
					std::string errMsg = "LPAlgorithmSHEFV::EvalMult without RelinKey is not applicable for FV SHE Scheme.";
					throw std::runtime_error(errMsg);
		}

		void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext, const LPEvalKey<Element> &EK) const;

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
