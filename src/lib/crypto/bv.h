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
	class LPCryptoParametersBV : public LPCryptoParametersRLWE<Element> {
		public:
			
			/**
			 * Constructor that initializes all values to 0.
			 */
			LPCryptoParametersBV() : LPCryptoParametersRLWE<Element>() {}

			/**
			 * Copy constructor.
			 *
			 */
			LPCryptoParametersBV(const LPCryptoParametersBV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {}

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
			LPCryptoParametersBV(
				shared_ptr<ElemParams> params,
				const BigBinaryInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				int depth = 1)
					: LPCryptoParametersRLWE<Element>(
						params,
						plaintextModulus,
						distributionParameter,
						assuranceMeasure,
						securityLevel,
						relinWindow,
						depth) {}

			/**
			* Destructor
			*/
			virtual ~LPCryptoParametersBV() {}
			
			//JSON FACILITY
			/**
			* Serialize the object into a Serialized
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @param fileFlag is an object-specific parameter for the serialization
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj) const {
				if( !serObj->IsObject() )
					return false;

				SerialItem cryptoParamsMap(rapidjson::kObjectType);
				if( this->SerializeRLWE(serObj, cryptoParamsMap) == false )
					return false;

				serObj->AddMember("LPCryptoParametersBV", cryptoParamsMap.Move(), serObj->GetAllocator());
				serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersBV", serObj->GetAllocator());

				return true;
			}

			/**
			* Populate the object from the deserialization of the Setialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj) {
				Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersBV");
				if( mIter == serObj.MemberEnd() ) return false;

				return this->DeserializeRLWE(mIter);
			}

			
			/**
			* == operator to compare to this instance of LPCryptoParametersLTV object. 
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersBV<Element> *el = dynamic_cast<const LPCryptoParametersBV<Element> *>(&rhs);

				if( el == 0 ) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}
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
		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
			Element &plaintext) const;

		/**
		* Method for decrypting plaintext using BV
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
	class LPAlgorithmPREBV : public LPPREAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
	public:

		//inherited constructors
		LPAlgorithmPREBV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
		LPAlgorithmPREBV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

		/**
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPrivateKey encryption key for the new ciphertext.
		* @param &origPrivateKey original private key used for decryption.
		* @param &ddg discrete Gaussian generator.
		* @param *evalKey the evaluation key.
		*/
		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPKey<Element>> newPrivateKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

		/**
		* Function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
		*
		* @param &evalKey the evaluation key.
		* @param &ciphertext the input ciphertext.
		* @param *newCiphertext the new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const;
	};


	/**
	* @brief Main public key encryption scheme for BV implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeBV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeBV() : LPPublicKeyEncryptionScheme<Element>() {}
		LPPublicKeyEncryptionSchemeBV(std::bitset<FEATURESETSIZE> mask);

		//These functions can be implemented later
		//Initialize(mask);

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
