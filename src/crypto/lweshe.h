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
	class LPAlgorithmSHELWENTRU : public LPAlgorithmAHELWENTRU<Element>, public LPSHEAlgorithm<Element> {
		public:
			
			/**
			 * Function for evaluation addition on ciphertext.
			 *
			 * @param &ciphertext1 the input ciphertext.
			 * @param &ciphertext2 the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			void EvalMult(const Ciphertext<Element> &ciphertext1, 
				const Ciphertext<Element> &ciphertext2, 
				Ciphertext<Element> *newCiphertext) const;

			/**
			 * Function to generate key switch hint on a ciphertext.
			 *
			 * @param &newPrivateKey private key for the new ciphertext.
			 * @param &origPrivateKey original private key used for decryption.
			 * @param depth used for decryption.
			 * @param &dgg discrete Gaussian generator.
			 * @param *keySwitchHint the key switch hint.
			 */
			 bool KeySwitchHintGen(const LPPrivateKey<Element> &newPrivateKey, 
				LPPrivateKey<Element> &origPrivateKey,
				usint depth,
				DiscreteGaussianGenerator &dgg, 
				LPKeySwitchHint<Element> *keySwitchHint) const;

			/**
			 * Function to generate key switch hint on a ciphertext for depth 2.
			 *
			 * @param &privateKey private key for the new ciphertext.
			 * @param &dgg discrete Gaussian generator.
			 * @param *keySwitchHint the key switch hint.
			 */
			 bool KeySwitchHintGen(const LPPrivateKey<Element> &newPrivateKey, 
				DiscreteGaussianGenerator &dgg, 
				LPKeySwitchHint<Element> *keySwitchHint) const;
			
			/**
			 * Function to define key switching operation
			 *
			 * @param &keySwitchHint the evaluation key.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			void KeySwitch(const LPKeySwitchHint<Element> &keySwitchHint,
				const Ciphertext<Element> &ciphertext, 
				Ciphertext<Element> *newCiphertext) const;

	};

} // namespace lbcrypto ends
#endif
