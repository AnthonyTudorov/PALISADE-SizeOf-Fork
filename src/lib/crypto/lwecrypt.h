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
#include "rlwe.h"
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
	 * @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAlgorithmLTV : public LPEncryptionAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
		public:

			/**
			* Default Constructor
			*/
			LPAlgorithmLTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
			/**
			* Constructor that initliazes the scheme
			*
			*@param &scheme 
			*/
			LPAlgorithmLTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

			/**
			 * Method for encrypting plaintext using Ring-LWE NTRU
			 *
			 * @param &publicKey public key used for encryption.
			 * @param &plaintext the plaintext input.
			 * @param *ciphertext ciphertext which results from encryption.
			 * @return an instance of EncryptResult related to the ciphertext that is encrypted.
			 */
			EncryptResult Encrypt(const LPPublicKey<Element> &publicKey,
				const Element &plaintext,
				Ciphertext<Element> *ciphertext) const;

			/**
			 * Method for decrypting plaintext using Ring-LWE NTRU
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return an instance of DecryptResult related to the plaintext that is decrypted
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
	 * @brief Concrete feature class for Leveled SHELTV operations
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPLeveledSHEAlgorithmLTV : public LPLeveledSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
		public:	
			/**
			* Default constructor
			*/
			LPLeveledSHEAlgorithmLTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
			/**
			* Constructor that initliazes the scheme
			*
			* @param &scheme is a reference to scheme
			*/
			LPLeveledSHEAlgorithmLTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

			/**
			 * Method for generating a KeySwitchHint
			 *
			 * @param &originalPrivateKey Original private key used for encryption.
			 * @param &newPrivateKey New private key to generate the keyswitch hint.
			 * @param *keySwitchHint is where the resulting keySwitchHint will be placed.
			 */
			virtual void KeySwitchHintGen(const LPPrivateKey<Element> &originalPrivateKey, const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *keySwitchHint) const ;
			/**
			 * Method for KeySwitching based on a KeySwitchHint
			 *
			 * @param &keySwitchHint Hint required to perform the ciphertext switching.
			 * @param &cipherText Original ciphertext to perform switching on.
			 */
			virtual Ciphertext<Element> KeySwitch(const LPEvalKeyNTRU<Element> &keySwitchHint,const  Ciphertext<Element> &cipherText) const;

			/**
			* Method for generating a keyswitchhint from originalPrivateKey square to newPrivateKey
			*
			* @param &originalPrivateKey that is (in method) squared for the keyswitchhint.
			* @param &newPrivateKey new private for generating a keyswitchhint to.
			* @param *quadraticKeySwitchHint the generated keyswitchhint.
			*/
			virtual void QuadraticKeySwitchHintGen(const LPPrivateKey<Element> &originalPrivateKey, const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *quadraticKeySwitchHint) const;
			
			/**
			 * Method for ModReducing CipherText and the Private Key used for encryption.
			 *
			 * @param *cipherText Ciphertext to perform and apply modreduce on.
			 */
			virtual void ModReduce(Ciphertext<Element> *cipherText) const; 
			/**
			 * Method for RingReducing CipherText and the Private Key used for encryption.
			 *
			 * @param *cipherText Ciphertext to perform and apply ringreduce on.
			 * @param *keySwitchHint is the keyswitchhint from the ciphertext's private key to a sparse key
			 */
			virtual void RingReduce(Ciphertext<Element> *cipherText, const LPEvalKeyNTRU<Element> &keySwitchHint) const ; 
			
			/**
			* Method for Composed EvalMult
			*
			* @param &cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
			* @param &cipherText2 cipherText2, second input ciphertext to perform multiplication on.
			* @param &quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
			* @param &cipherTextResult is the resulting ciphertext that can be decrypted with the secret key of the particular level.
			*/
			virtual void ComposedEvalMult(const Ciphertext<Element> &cipherText1, const Ciphertext<Element> &cipherText2, const LPEvalKeyNTRU<Element> &quadKeySwitchHint, Ciphertext<Element> *cipherTextResult) const ;

			/**
			* Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
			*
			* @param &cipherText1 is the original ciphertext to be key switched and mod reduced.
			* @param &linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
			* @param &cipherTextResult is the resulting ciphertext.
			*/
			virtual void LevelReduce(const Ciphertext<Element> &cipherText1, const LPEvalKeyNTRU<Element> &linearKeySwitchHint, Ciphertext<Element> *cipherTextResult) const ;
			/**
			* Function to generate sparse public and private keys. By sparse it is meant that all even indices are non-zero
			* and odd indices are set to zero.
			*
			* @param *publicKey is the public key to be generated.
			* @param *privateKey is the private key to be generated.
			*/
			virtual bool SparseKeyGen(LPPublicKey<Element> *publicKey, LPPrivateKey<Element> *privateKey) const;
	};

	/**
	 * @brief Encryption algorithm implementation template for Stehle-Stenfeld scheme,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPEncryptionAlgorithmStehleSteinfeld : public LPAlgorithmLTV<Element> {
		public:

			/**
			* Default constructor
			*/
			LPEncryptionAlgorithmStehleSteinfeld() : LPAlgorithmLTV<Element>(){};
			/**
			* Constructor that initliazes the scheme
			*
			* @param &scheme is a reference to scheme
			*/
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
			LPPublicKeyEncryptionSchemeLTV() : LPPublicKeyEncryptionScheme<Element>() {}
			LPPublicKeyEncryptionSchemeLTV(std::bitset<FEATURESETSIZE> mask);

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
			LPPublicKeyEncryptionSchemeStehleSteinfeld() : LPPublicKeyEncryptionSchemeLTV<Element>() {}
			LPPublicKeyEncryptionSchemeStehleSteinfeld(std::bitset<FEATURESETSIZE> mask);

			void Enable(PKESchemeFeature feature);
	};

	/**
	* @brief placeholder for KeySwitchHints, both linear and quadratic, for Leveled SHE operations. Both linear and quadratic keys
	* are stored in two separate vectors. The order in of keys in ascending order is the order of keys required for computation at each level
	* of a leveled SHE operation.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPLeveledSHEKeyStructure //: TODO: NISHANT to implement serializable public Serializable
	{
	private:
		std::vector< LPEvalKeyNTRU<Element> > m_qksh;
		std::vector< LPEvalKeyNTRU<Element> > m_lksh;
		usint m_levels;

	public:
		/**
		*Constructor that initliazes the number of computation levels
		*
		* @param levels number of levels
		*/
		explicit LPLeveledSHEKeyStructure(usint levels) : m_levels(levels) { m_qksh.reserve(levels); m_lksh.reserve(levels);};
		
		/**
		*Get method for LinearKeySwitchHint for a particular level
		*
		*@return the LinearKeySwitchHint for the level
		*/
		const LPEvalKeyNTRU<Element>& GetLinearKeySwitchHintForLevel(usint level) const {
			if(level>m_levels-1) {
				throw std::runtime_error("Level out of range");
			} 
			else {
				return m_lksh[level];
			} 
		};
		/**
		*Get method for QuadraticKeySwitchHint for a particular level
		*
		*@return the QuadraticKeySwitchHint for the level
		*/
		const LPEvalKeyNTRU<Element>& GetQuadraticKeySwitchHintForLevel(usint level) const {
			if(level>m_levels-1) {
				throw std::runtime_error("Level out of range");
			} 
			else {
				return m_qksh[level];
			} 
		}
		/**
		* Method to add a LinearKeySwitchHint. The added key will be the key for the last level
		*
		*@param &lksh LinearKeySwitchHintLTV to be added.
		*/
		void PushBackLinearKey(const LPEvalKeyNTRU<Element> &lksh){
			m_lksh.push_back(std::move(lksh));
		}
		/**
		* Method to add a QuadraticKeySwitchHint. The added key will be the key for the last level
		*
		*@param &quad QuadraticKeySwitchHintLTV to be added.
		*/
		void PushBackQuadraticKey(const LPEvalKeyNTRU<Element> &quad){
			m_qksh.push_back(std::move(quad));
		}
		/**
		* Method to set LinearKeySwitchHint for a particular level of computation.
		*
		*@param &lksh LinearKeySwitchHintLTV to be set.
		*@param level is the level to set the key to.
		*/
		void SetLinearKeySwitchHintForLevel(const LPEvalKeyNTRU<Element> &lksh, usint level) {
			if(level>m_levels-1) {
				throw std::runtime_error("Level out of range");
			} 
			else { 
				m_lksh[level] = lksh;
			}
		}
		/**
		* Method to set QuadraticKeySwitchHint for a particular level of computation.
		*
		*@param &qksh QuadraticKeySwitchHint to be set.
		*@param level is the level to set the key to.
		*/
		void SetQuadraticKeySwitchHintForLevel(const LPEvalKeyNTRU<Element> &qksh, usint level) { if(level>m_levels-1) {throw std::runtime_error("Level out of range");} else { m_qksh[level] = qksh;} };
	};
} // namespace lbcrypto ends
#endif
