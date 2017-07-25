/*
 * @file pubkeylp.cpp - public key implementation
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */
 
#include "cryptocontext.h"
#include "pubkeylp.h"

namespace lbcrypto {

	template<typename Element>
	std::vector<usint> LPSHEAlgorithm<Element>::GenerateIndices_2n(usint batchSize) const {

		// stores automorphism indices needed for EvalSum
		std::vector<usint> indices;

		usint g = 5;
		for (int i = 0; i < floor(log2(batchSize)) - 1; i++)
		{
			indices.push_back(g);
			g = (g * g) % m;
		}
		indices.push_back(3);

		return indices;

	}

	template<typename Element>
	void LPSHEAlgorithm<Element>::EvalSum_2n(usint batchSize, const std::map<usint, shared_ptr<LPEvalKey<Element>>> &evalKeys, 
		shared_ptr<Ciphertext<Element>> newCiphertext) const {

		usint g = 5;
		for (int i = 0; i < floor(log2(batchSize)) - 1; i++)
		{
			newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, g, evalKeys));
			g = (g * g) % m;
		}
		newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, 3, evalKeys));

	}

}
