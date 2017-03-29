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
 * http://dx.doi.org/10.1007/978-3-642-22792-9_29). 
 * The levelled Homomorphic scheme (BGV) is described in
 * "Fully Homomorphic Encryption without Bootstrapping", Internet Source : https://eprint.iacr.org/2011/277.pdf .
 * Implementation details are provided in
 * "Homomorphic Evaluation of the AES Circuit" Internet source : https://eprint.iacr.org/2012/099.pdf .
 */


#ifndef LBCRYPTO_CRYPTO_BV_H
#define LBCRYPTO_CRYPTO_BV_H

//Includes Section
#include "palisade.h"

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
			 * Default Constructor.
			 */
			LPCryptoParametersBV() : LPCryptoParametersRLWE<Element>() {
				m_mode = RLWE;
			}

			/**
			 * Copy constructor.
			 *
			 */
			LPCryptoParametersBV(const LPCryptoParametersBV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
				m_mode = rhs.m_mode;
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
			 * @param mode sets the mode of operation: RLWE or OPTIMIZED
			 * @param depth depth which is set to 1.
			 */
			LPCryptoParametersBV(
				shared_ptr<typename Element::Params> params,
				const BigBinaryInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				MODE mode,
				int depth = 1)
					: LPCryptoParametersRLWE<Element>(
						params,
						plaintextModulus,
						distributionParameter,
						assuranceMeasure,
						securityLevel,
						relinWindow,
						depth) {
				m_mode = mode;		
			}

			/**
			* Destructor.
			*/
			virtual ~LPCryptoParametersBV() {}
			
			/**
			* Serialize the object into a Serialized
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj) const;

			/**
			* Populate the object from the deserialization of the Serialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj);

			/**
			* Gets the mode setting: RLWE or OPTIMIZED.
			*
			* @return the mode setting.
			*/
			MODE GetMode() const { return m_mode; }

			/**
			* Configures the mode for generating the secret key polynomial
			*/
			void SetMode(MODE mode) { m_mode = mode; }

			/**
			* == operator to compare to this instance of LPCryptoParametersBV object.
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersBV<Element> *el = dynamic_cast<const LPCryptoParametersBV<Element> *>(&rhs);

				if (el == 0) return false;

				if (m_mode != el->m_mode) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

	private:
		// specifies whether the keys are generated from discrete 
		// Gaussian distribution or ternary distribution with the norm of unity
		MODE m_mode;

	};


	/**
	* @brief Encryption algorithm implementation template for BV-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmBV : public LPEncryptionAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmBV() {};

		/**
		* Method for encrypting plaintext using BV Scheme
		*
		* @param publicKey is the public key used for encryption.
		* @param &plaintext the plaintext input.
		* @return ciphertext which results from encryption.
		*/
		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
			Element &plaintext) const;

		/**
		* Method for decrypting plaintext using BV
		*
		* @param &privateKey private key used for decryption.
		* @param &ciphertext ciphertext id decrypted.
		* @param *plaintext the plaintext output.
		* @return the success/fail result
		*/
		DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const shared_ptr<Ciphertext<Element>> ciphertext,
			Element *plaintext) const;

		/**
		* Function to generate public and private keys
		*
		* @param cc is the cryptoContext which encapsulates the crypto paramaters.
		* @param makeSparse is a boolean flag that species if the key is sparse(interleaved zeroes) or not.
		* @return KeyPair containting private key and public key.
		*/
		LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse=false) const;

	};

	/**
	* Class for evaluation of homomorphic operations.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEBV : public LPSHEAlgorithm<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmSHEBV() {}

		/**
		* Function for homomorphic addition of ciphertexts.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return result of homomorphic addition of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		*
		* @param ciphertext1 the input ciphertext.
		* @param ciphertext2 the input ciphertext.
		* @return result of homomorphic subtraction of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1, 
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		/**
		* Function for homomorphic multiplication of ciphertexts without key switching.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return result of homomorphic multiplication of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		/**
		* Function for homomorphic multiplication of ciphertexts followed by key switching operation.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @return result of homomorphic multiplication of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2,
			const shared_ptr<LPEvalKey<Element>> ek) const;

		/**
		* Function for homomorphic negation of ciphertexts.
		*
		* @param ct first input ciphertext.
		* @return new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Method for generating a KeySwitchHint using RLWE relinearization (based on the RLWE assumption only)
		*
		* @param originalPrivateKey is the original private key used for encryption.
		* @param newPrivateKey is the new private key to generate the keyswitch hint.
		* @return resulting keySwitchHint to switch the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey, 
			const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const;

		/**
		* Method for KeySwitching based on a KeySwitchHint - uses the RLWE relinearization
		*
		* @param keySwitchHint Hint required to perform the ciphertext switching.
		* @param cipherText Original ciphertext to perform switching on.
		* @return cipherText decryptable by new private key.
		*/
		shared_ptr<Ciphertext<Element>> KeySwitch(const shared_ptr<LPEvalKey<Element>> keySwitchHint, 
			const shared_ptr<Ciphertext<Element>> cipherText) const;

		/**
		* Method for KeySwitching based on NTRU key generation and RLWE relinearization. Not used for BV.
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchRelinGen(const shared_ptr<LPPublicKey<Element>> newPublicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
			std::string errMsg = "LPAlgorithmSHEBV:KeySwitchRelinGen is not implemented for BV as relinearization is the default technique and no NTRU key generation is used in BV.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for KeySwitching based on NTRU key generation and RLWE relinearization. Not used for BV.
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		shared_ptr<Ciphertext<Element>> KeySwitchRelin(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const {
			std::string errMsg = "LPAlgorithmSHEBV:KeySwitchRelin is not implemented for BV as relinearization is the default technique and no NTRU key generation is used in BV.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function to generate key switch hint on a ciphertext for depth 2.
		*
		* @param originalPrivateKey is the original private key used for generating ciphertext.
		* @return keySwitchHint generated to switch the ciphertext.
		*/
		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const;

		/**
		* Function for evaluating ciphertext at an index; works only with odd indices in the ciphertext.
		* Currently not implemented for BV.
		*
		* @param ciphertext the input ciphertext.
		* @param i index of the item to be "extracted", starts with 2.
		* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
		*/
		shared_ptr<Ciphertext<Element>> EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext, const usint i,
			const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const {
			std::string errMsg = "LPAlgorithmSHEBV::EvalAtIndex is not implemented for BV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}


		/**
		* Generate automophism keys for a given private key; works only with odd indices in the ciphertext.
		* Currently not implemented for BV.
		*
		* @param &publicKey original public key.
		* @param &origPrivateKey original private key.
		* @param size number of automorphims to be computed; starting from plaintext index 2; maximum is n/2-1
		* @param *tempPrivateKey used to store permutations of private key; passed as pointer because instances of LPPrivateKey cannot be created within the method itself
		* @param *evalKeys the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
		*/
		bool EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey,
			const usint size, shared_ptr<LPPrivateKey<Element>> *tempPrivateKey,
			std::vector<shared_ptr<LPEvalKey<Element>>> *evalKeys) const {
			std::string errMsg = "LPAlgorithmSHEBV::EvalAutomorphismKeyGen  is not implemented for BV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}
	};

	/**
	* @brief PRE scheme based on BV.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmPREBV : public LPPREAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmPREBV() {}

		/**
		* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
		* Variant that uses the new secret key directly.
		*
		* @param newKey new private key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

		/**
		* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
		* Variant that uses the public key for the new secret key.
		*
		* @param newKey public key for the new private key.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPublicKey<Element>> newKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
			std::string errMsg = "LPAlgorithmPREBV::ReKeyGen using a public key of the new secret key is not implemented for the BV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function to define the re-encryption method using the evaluation key generated by ReKeyGen
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return resulting ciphertext after the re-encryption operation.
		*/
		shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const;
	};


	/**
	* @brief Concrete feature class for Leveled SHEBV operations. This class adds leveled (BGV scheme) features to the BV scheme.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPLeveledSHEAlgorithmBV : public LPLeveledSHEAlgorithm<Element> {
	public:
		/**
		* Default constructor
		*/
		LPLeveledSHEAlgorithmBV() {}

		/**
		* Method for ModReducing CipherText.
		*
		* @param cipherText is the ciphertext to perform modreduce on.
		* @return ciphertext after the modulus reduction performed.
		*/
		virtual shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const;

		/**
		* Method for RingReducing CipherText. Not implemented for the BV/BGV scheme.
		*
		* @param cipherText is the ciphertext to perform ringreduce on.
		* @param keySwitchHint is the keyswitchhint to switch the ciphertext from original private key to a sparse private key.
		*/
		virtual shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const {

			std::string errMsg = "LPAlgorithmSHEBV::RindReduce is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for Composed EvalMult, which includes homomorphic multiplication, key switching, and modulo reduction. Not implemented for the BV/BGV scheme.
		*
		* @param cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
		* @param cipherText2 cipherText2, second input ciphertext to perform multiplication on.
		* @param quadKeySwitchHint is used for EvalMult operation.
		* @return resulting ciphertext.
		*/
		virtual shared_ptr<Ciphertext<Element>> ComposedEvalMult(
			const shared_ptr<Ciphertext<Element>> cipherText1,
			const shared_ptr<Ciphertext<Element>> cipherText2,
			const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const
		{
			std::string errMsg = "LPAlgorithmSHEBV::ComposedEvalMult is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
		* Not implemented for the BV/BGV scheme.
		*
		* @param cipherText1 is the original ciphertext to be key switched and mod reduced.
		* @param linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
		* @return resulting ciphertext.
		*/
		virtual shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
			const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const 
		{
			std::string errMsg = "LPAlgorithmSHEBV::LevelReduce is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function that determines if security requirements are met if ring dimension is reduced by half.
		* Not implemented for the BV/BGV scheme.
		*
		* @param ringDimension is the original ringDimension
		* @param &moduli is the vector of moduli that is used
		* @param rootHermiteFactor is the security threshold
		* @return boolean value that determines if the ring is reducable.
		*/
		virtual bool CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const
		{
			std::string errMsg = "LPAlgorithmSHEBV::CanRingReduce is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}
	};


	/**
	* @brief Main public key encryption scheme for the BV/BGV implementation
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeBV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeBV() : LPPublicKeyEncryptionScheme<Element>() {}
		LPPublicKeyEncryptionSchemeBV(std::bitset<FEATURESETSIZE> mask);

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
