/**
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
 * This code provides the core somewhat homomorphic encryption functionality.
 */

#ifndef LBCRYPTO_CRYPTO_LWESHE_H
#define LBCRYPTO_CRYPTO_LWESHE_H

//Includes Section
#include "pubkeylp.h"
#include "../utils/inttypes.h"
#include "lwecrypt.h"
#include "lweahe.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	/**
	 * Evaluation multiplication for homomorphic encryption operations.
	 *
	 * @brief Template for crypto PRE.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAlgorithmSHELTV : public LPSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
		public:

			/**
			* Default constructor
			*/
			LPAlgorithmSHELTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
			/**
			* Constructor that initliazes the scheme
			*
			* @param &scheme is a reference to scheme
			*/
			LPAlgorithmSHELTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

			/**
			 * Function for evaluating multiplication on ciphertext.
			 *
			 * @param &ciphertext1 first input ciphertext.
			 * @param &ciphertext2 second input ciphertext.
			 * @param *newCiphertext the new resulting ciphertext.
			 */
			void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2, 
				Ciphertext<Element> *newCiphertext) const;

			bool EvalMultKeyGen(const LPPrivateKey<Element> &privateKey,
				LPEvalKey<Element> *evalKey) const {
					std::string errMsg = "LPAlgorithmSHELTV::EvalMultKeyGen is not applicable for LTV SHE Scheme.";
					throw std::runtime_error(errMsg);
			}
		
			void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext, const LPEvalKey<Element> &evalKey) const {
					std::string errMsg = "LPAlgorithmSHELTV::EvalMult with RelinKey is not applicable for LTV SHE Scheme.";
					throw std::runtime_error(errMsg);
			}

			/**
			* Function for evaluating multiplication on ciphertext followed by key switching operation.
			*
			* @param &ciphertext1 first input ciphertext.
			* @param &ciphertext2 second input ciphertext.
			* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2. 
			* @param *newCiphertext the new resulting ciphertext.
			*/
			void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,const LPEvalKey<Element> &ek,
				Ciphertext<Element> *newCiphertext) const;

			/**
			 * Function for evaluation addition on ciphertext.
			 *
			 * @param &ciphertext1 first input ciphertext.
			 * @param &ciphertext2 second input ciphertext.
			 * @param *newCiphertext the new resulting ciphertext.
			 */

			void EvalAdd(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const ;

			/**
			 * Function to generate key switch hint on a ciphertext.
			 *
			 * @param &newPrivateKey private key for the new ciphertext.
			 * @param &origPrivateKey original private key used for decryption.
			 * @param depth used for decryption.
			 * @param *keySwitchHint the key switch hint.
			 */
			 bool EvalMultKeyGen(const LPPrivateKey<Element> &newPrivateKey, 
				LPPrivateKey<Element> &origPrivateKey,
				usint depth, 
				LPEvalKeyNTRU<Element> *keySwitchHint) const;

			/**
			 * Function to generate key switch hint on a ciphertext for depth 2.
			 *
			 * @param &newPrivateKey private key for the new ciphertext.
			 * @param *keySwitchHint the key switch hint.
			 */
			 bool EvalMultKeyGen(const LPPrivateKey<Element> &newPrivateKey, 
				LPEvalKeyNTRU<Element> *keySwitchHint) const;
			
			/**
			 * Function to define key switching operation
			 *
			 * @param &keySwitchHint the evaluation key.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			void KeySwitch(const LPEvalKeyNTRU<Element> &keySwitchHint,
				const Ciphertext<Element> &ciphertext, 
				Ciphertext<Element> *newCiphertext) const;

	};

} // namespace lbcrypto ends
#endif
