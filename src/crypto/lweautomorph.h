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
 * This code provides the core proxy re-encryption functionality.
 */

#ifndef LBCRYPTO_CRYPTO_LWEAUTOMORPH_H
#define LBCRYPTO_CRYPTO_LWEAUTOMORPH_H

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
	 * Automorphism-based SHE operations.
	 *
	 * @brief Template for crypto PRE.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAlgorithmAutoMorphLWENTRU : public LPAutoMorphAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
		public:

			//inherited constructors
			LPAlgorithmAutoMorphLWENTRU() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
			LPAlgorithmAutoMorphLWENTRU(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};
			
			/**
			 * Function for evaluating ciphertext at an index; works only with odd indices in the ciphertext
			 *
			 * @param &ciphertext the input ciphertext.
			 * @param i index of the item to be "extracted", starts with 2.
			 * @param evalkeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
			 * @param *newCiphertext the new ciphertext.
			 */
			void EvalAtIndex(const Ciphertext<Element> &ciphertext, const usint i, const std::vector<LPEvalKey<Element> *> &evalKeys, 
				Ciphertext<Element> *newCiphertext) const;

			/**
			 * Generate automophism keys for a given private key; works only with odd indices in the ciphertext
			 *
			 * @param &publicKey original public key.
			 * @param &origPrivateKey original private key.
			 * @param &ddg discrete Gaussian generator.
			 * @param size number of automorphims to be computed; starting from plaintext index 2; maximum is m/2-1
			 * @param *tempPrivateKey used to store permutations of private key; passed as pointer because instances of LPPrivateKey cannot be created within the method itself
			 * @param *evalKeys the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
			 */
			virtual bool EvalAutomorphismKeyGen(const LPPublicKey<Element> &publicKey, 
				const LPPrivateKey<Element> &origPrivateKey,
				DiscreteGaussianGenerator &ddg, const usint size, LPPrivateKey<Element> *tempPrivateKey, 
				std::vector<LPEvalKey<Element> *> *evalKeys) const;

	};

} // namespace lbcrypto ends
#endif
