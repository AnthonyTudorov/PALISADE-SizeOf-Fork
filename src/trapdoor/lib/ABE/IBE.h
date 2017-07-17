/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 * @programmer Erkay Savas
 * @version 00_05
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
 * This code provides functionality for Identity-based encryption (IBE). IBE is like a one attribute CP-ABE
 * The algorithms and some of the naming convenstions are based on the paper in
 * https://link.springer.com/content/pdf/10.1007/978-3-642-34704-7.pdf#page=333
 */

#ifndef TRAPDOOR_LIB_IBE_IBE_H_
#define TRAPDOOR_LIB_IBE_IBE_H_

#include <cmath>
#include <vector>
#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "math/backend.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "../sampling/trapdoor.h"
#include "../sampling/trapdoor.cpp"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	class IBE{
		public:

			/**
			 * Default Constructor
			 *
			 */
			IBE(){}

			/**
			 * Destructor
			 *
			 */
			~IBE() { }
			/**
			* Setup function for Private Key Generator (PKG)
			*
			* @param ilParams parameter set
			* @param base is a power of two
			* @param &dug
			*/
			std::pair<RingMat, RLWETrapdoorPair<Poly>> Setup(
				const shared_ptr<ILParams> ilParams,
				int32_t base,
				const DiscreteUniformGenerator &dug  // select according to uniform distribution
			);
			/**
			* Setup function for all parties except the Private Key Generator (PKG)
			*
			* @param ilParams parameter set
			* @param base is a power of two
			*/
			void Setup(
				const shared_ptr<ILParams> ilParams,
				int32_t base
			);
			/**
			* KeyGen Function
			*
			* @param ilParams parameter set
			* @param &pubA TBD
			* @param &u TBD public element d sampled as dug
			* @param &secTA secret component of trapdoor
			* @param &dgg to generate error terms (Gaussian)
			* @param *sk secret key
			*/
			void KeyGen(
				const shared_ptr<ILParams> ilParams,
				const RingMat &pubA,
				const Poly &u,
				const RLWETrapdoorPair<Poly> &secTA,
				DiscreteGaussianGenerator &dgg,
				RingMat *sk
			);
			/**
			* Encrypt Function
			*
			* @param ilParams parameter set
			* @param &pubA public element TBD
			* @param &u TBD public element d sampled as dug
			* @param &ptext plaintext
			* @param &dgg to generate error terms (Gaussian)
			* @param &dug select according to uniform distribution
			* @param &bug select according to uniform distribution binary
			* @param *ctC0 ciphertext C0
			* @param *ctC1 ciphertext C1
			*/
			void Encrypt(
				const shared_ptr<ILParams> ilParams,
				const RingMat &pubA,
				const Poly &u,
				const Poly &ptext,
				const DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
				DiscreteUniformGenerator &dug,  // select according to uniform distribution
				const BinaryUniformGenerator &bug,    // select according to uniform distribution binary
				RingMat *ctC0,
				Poly *ctC1
			);
			/**
			* Decrypt Function
			*
			* @param ilParams parameter set
			* @param &sk secret key
			* @param &ctC0 c0
			* @param &ctC1 c1
			* *dtext decrypted ciphertext
			*/
			void Decrypt(
				const shared_ptr<ILParams> ilParams,
				const RingMat &sk,
				const RingMat &ctC0,
				const Poly &ctC1,
				Poly *dtext
			);

		private:
			usint m_k; //number of bits of the modulus
			usint m_N; // ring dimension
			BigInteger m_q; // modulus
			usint m_m; // m = k+2
			usint m_base;
	};
}

int IBE_Test(int iter, int32_t base);

#endif /* TRAPDOOR_LIB_CPABE_ABE_H_ */
