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

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

template <class Element>
	class IBE{
		public:

			/**
			 * Default Constructor
			 *
			 */
			IBE(): m_N(0), m_m(0){}

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
			*/
			std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> SetupPKG(
				const shared_ptr<typename Element::Params> ilParams,
				int32_t base
			);
			/**
			* Setup function for all parties except the Private Key Generator (PKG)
			*
			* @param ilParams parameter set
			* @param base is a power of two
			*/
			void SetupNonPKG(
				const shared_ptr<typename Element::Params> ilParams,
				int32_t base
			);
			/**
			* KeyGen Function
			*
			* @param &pubA public Matrix A
			* @param &pubElemD public element d sampled as dug
			* @param &secTA secret component of trapdoor
			* @param &dgg to generate error terms (Gaussian)
			* @param *sk secret key
			*/
			void KeyGen(
				const Matrix<Element> &pubA,
				const Element &pubElemD,
				const RLWETrapdoorPair<Element> &secTA,
				typename Element::DggType &dgg,
				Matrix<Element> *sk
			);

			/**
			* KeyGenOffline Function
			*
			* @param &secTA secret component of trapdoor
			* @param &dgg to generate error terms (Gaussian)
			*
			* @return perturbation vector
			*/
			shared_ptr<Matrix<Element>> KeyGenOffline(
				const RLWETrapdoorPair<Element> &secTA,
				typename Element::DggType &dgg
			);

			/**
			* KeyGenOnline Function
			*
			* @param &pubA public Matrix A
			* @param &pubElemD public element d sampled as dug
			* @param &secTA secret component of trapdoor
			* @param &dgg to generate error terms (Gaussian)
			* @param perturbationVector pre-computed perturbation vector
			* @param *sk secret key
			*/
			void KeyGenOnline(
				const Matrix<Element> &pubA,
				const Element &pubElemD,
				const RLWETrapdoorPair<Element> &secTA,
				typename Element::DggType &dgg,
				const shared_ptr<Matrix<Element>> perturbationVector,
				Matrix<Element> *sk
			);
			/**
			* Encrypt Function
			*
			* @param ilParams parameter set
			* @param &pubA public element
			* @param &pubElemD  public element d sampled as dug
			* @param &ptext plaintext
			* @param &dug select according to uniform distribution
			* @param *ctC0 ciphertext C0
			* @param *ctC1 ciphertext C1
			*/
			void Encrypt(
				const shared_ptr<typename Element::Params> ilParams,
				const Matrix<Element> &pubA,
				const Element &pubElemD,
				const Element &ptext,
				typename Element::DugType &dug,  // select according to uniform distribution
				Matrix<Element> *ctC0,
				Element *ctC1
			);
			/**
			* Decrypt Function
			*
			* @param &sk secret key
			* @param &ctC0 c0
			* @param &ctC1 c1
			* @param *dtext decrypted ciphertext
			*/
			void Decrypt(
				const Matrix<Element> &sk,
				const Matrix<Element> &ctC0,
				const Element &ctC1,
				Element *dtext
			);

		private:
			usint m_k; //number of bits of the modulus
			usint m_N; // ring dimension
			typename Element::Integer m_q; // modulus
			usint m_m; // m = k+2
			usint m_base;
	};
}

#endif /* TRAPDOOR_LIB_CPABE_ABE_H_ */
