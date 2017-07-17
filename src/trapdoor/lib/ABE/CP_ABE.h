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
 * This code provides functionality for Ciphertext-policy attribute based encryption (CP-ABE). The
 * algorithms and some of the naming convenstions are based on the paper in
 * https://link.springer.com/content/pdf/10.1007/978-3-642-34704-7.pdf#page=333
 */

#ifndef TRAPDOOR_LIB_CPABE_ABE_H_
#define TRAPDOOR_LIB_CPABE_ABE_H_

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

	class CPABE{
		public:

			/**
			 * Default Constructor
			 *
			 * */
			CPABE(){}
			/**
			 * Destructor for releasing dynamic memory
			 *
			 */
			~CPABE() { }
			/**
			* Setup function for Private Key Generator (PKG)
			*
			* @param ilParams parameter set
			* @param base is a power of two
			* @param ell total number of attributes
			* @param &dug
			* @param *u TBD public element d sampled as dug
			* @param *pubElemBPos is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to one
			* @param *pubElemBNeg is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to zero
			*/
			std::pair<RingMat, RLWETrapdoorPair<Poly>> Setup(
				const shared_ptr<ILParams> ilParams,
				int32_t base,
				const usint ell, // number of attributes
				const DiscreteUniformGenerator &dug,  // select according to uniform distribution
				Poly *u, //TBD
				RingMat *pubElemBPos,
				RingMat *pubElemBNeg
			);
			/**
			* Setup function for all parties except the Private Key Generator (PKG)
			*
			* @param ilParams parameter set
			* @param base is a power of two
			* @param ell total number of attributes
			*/
			void Setup(
				const shared_ptr<ILParams> ilParams,
				int32_t base,
				const usint ell
			);
			/**
			* KeyGen Function
			*
			* @param ilParams parameter set
			* @param &s[] Access rights of the user {0, 1}
			* @param &pubTA Public parameter of trapdoor
			* @param &pubElemBPos is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to one
			* @param *pubElemBNeg is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to zero
			* @param &u TBD public element d sampled as dug
			* @param &secTA secret component of trapdoor
			* @param &dgg to generate error terms (Gaussian)
			* @param *sk secret key
			*/
			void KeyGen(
				const shared_ptr<ILParams> ilParams,
				const usint s[],							//
				const RingMat &pubTA,                         // Public trapdoor parameter
				const RingMat &pubElemBPos,                         // Public parameter $B \in R_q^{ell \times k}$
				const RingMat &pubElemBNeg,                         // Public parameter $B \in R_q^{ell \times k}$
				const Poly &u,                  // public key $d \in R_q$
				const RLWETrapdoorPair<Poly> &secTA, // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
				DiscreteGaussianGenerator &dgg,          // to generate error terms (Gaussian)
				RingMat *sk                           // Secret key
			);
			/**
			* Encrypt Function
			*
			* @param ilParams parameter set
			* @param &pubTA public element of trapdoor
			* @param &pubElemBPos is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to one
			* @param &pubElemBNeg is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to zero
			* @param &u TBD public element d sampled as dug
			* @param w[] access structure
			* @param &ptext plaintext
			* @param &dgg to generate error terms (Gaussian)
			* @param &dug select according to uniform distribution
			* @param &bug select according to uniform distribution binary
			* @param *ctW ciphertext for attributes that are part of the attribute set w
			* @param *ctPos ciphertext based on B positive for attributes not access structure w
			* @param *ctNeg ciphertext based on B negative for attributes not access structure w
			* @param *ctC1 B^t * s + e0 part of CP-ABE algorithm for encryption/decryption
			*/
			void Encrypt(
				shared_ptr<ILParams> ilParams,
				const RingMat &pubTA,
				const RingMat &pubElemBPos,
				const RingMat &pubElemBNeg,
				const Poly &u,
				const int w[],
				const Poly &ptext,
				DiscreteGaussianGenerator &dgg,
				DiscreteUniformGenerator &dug,
				BinaryUniformGenerator &bug,
				RingMat *ctW,
				RingMat *ctPos,
				RingMat *ctNeg,
				Poly *ctC1
			);
			/**
			* Decrypt Function
			*
			* @param ilParams parameter set
			* @param w[] access structure
			* @param s[] user attributes
			* @param &sk secret key
			* @param &ctW for attributes that are part of the attribute set w
			* @param &ctPos ciphertext based on B positive for attributes not access structure w
			* @param &ctNeg ciphertext based on B negative for attributes not access structure w
			* @param &ctC1 B^t * s + e0 part of CP-ABE algorithm for encryption/decryption
			* @param *dtext decrypted ciphertext
			*/
			void Decrypt(
				const shared_ptr<ILParams> ilParams,
				const int w[],
				const usint s[],
				const RingMat &sk,
				const RingMat &ctW,
				const RingMat &ctPos,
				const RingMat &ctNeg,
				const Poly &ctC1,
				Poly *dtext
			);

		private:
			usint m_k; //number of bits of the modulus
			usint m_ell; //number of attributes
			usint m_N; // ring dimension
			BigInteger m_q; // modulus
			usint m_m; // m = k+2
			usint m_base;
	};
}

int CPABE_Test(usint iter);

#endif /* TRAPDOOR_LIB_CPABE_ABE_H_ */
