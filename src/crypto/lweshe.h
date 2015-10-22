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
	 * @tparam T a ring element.
	 * @tparam P a set of element parameters.
	 */
	template <class T, class P>
	class LPAlgorithmSHELWENTRU : public LPAlgorithmAHELWENTRU<T,P>, public LPSHEAlgorithm<T,P> {
		public:
			typedef T Element;		/**< The ring element */
			typedef P ElementParams;	/**< The ring element params */
			
			/**
			 * Function for evaluation addition on ciphertext.
			 *
			 * @param &ciphertext1 the input ciphertext.
			 * @param &ciphertext2 the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			void EvalMult(const LPCryptoParameters<Element,ElementParams> &params,
				const Element &ciphertext1, 
				const Element &ciphertext2, 
				Element *newCiphertext) const;

		protected:

			/**
			 * Function to generate key switch hint on a ciphertext.
			 *
			 * @param &newPrivateKey private key for the new ciphertext.
			 * @param &origPrivateKey original private key used for decryption.
			 * @param &ddg discrete Gaussian generator.
			 * @param *keySwitchHint the key switch hint.
			 */
			 bool KeySwitchHintGen(const LPPrivateKey<Element,ElementParams> &newPrivateKey, 
				LPPrivateKey<Element,ElementParams> &origPrivateKey,
				DiscreteGaussianGenerator &ddg, std::vector<Element> *keySwitchHint) const;
			
			/**
			 * Function to define key switching operation
			 *
			 * @param &keySwitchHint the evaluation key.
			 * @param &params re-ecryption parameters.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			void KeySwitch(const std::vector<Element> &keySwitchHint,
				const LPCryptoParameters<Element,ElementParams> &params,
				const Element &ciphertext, 
				Element *newCiphertext) const;

	};

} // namespace lbcrypto ends
#endif
