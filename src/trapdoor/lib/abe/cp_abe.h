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

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {
template <class Element>
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
		* @param *pubElemD public element d sampled as dug
		* @param *pubElemBPos is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to one
		* @param *pubElemBNeg is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to zero
		*/
		std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> Setup(
			const shared_ptr<typename Element::Params> ilParams,
			int32_t base,
			const usint ell,
			const typename Element::DugType &dug,
			Element *pubElemD,
			Matrix<Element> *pubElemBPos,
			Matrix<Element> *pubElemBNeg
		);
		/**
		* Setup function for all parties except the Private Key Generator (PKG)
		*
		* @param elementParams parameter set
		* @param base is a power of two
		* @param ell total number of attributes
		*/
		void Setup(
			const shared_ptr<typename Element::Params> elementParams,
			int32_t base,
			const usint ell
		);
		/**
		* KeyGen Function
		*
		* @param elementParams parameter set
		* @param &s[] Access rights of the user {0, 1}
		* @param &pubTA Public parameter of trapdoor
		* @param &pubElemBPos is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to one
		* @param *pubElemBNeg is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to zero
		* @param &pubElemD public element d sampled as dug
		* @param &secTA secret component of trapdoor
		* @param &dgg to generate error terms (Gaussian)
		* @param *sk secret key
		*/
		void KeyGen(
			const shared_ptr<typename Element::Params> elementParams,
			const usint s[],
			const Matrix<Element> &pubTA,
			const Matrix<Element> &pubElemBPos,
			const Matrix<Element> &pubElemBNeg,
			const Element &pubElemD,
			const RLWETrapdoorPair<Element> &secTA,
			typename Element::DggType &dgg,
			Matrix<Element> *sk
		);

		/**
		* KeyGen Function
		*
		* @param elementParams parameter set
		* @param &s[] Access rights of the user {0, 1}
		* @param &pubTA Public parameter of trapdoor
		* @param &pubElemBPos is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to one
		* @param *pubElemBNeg is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to zero
		* @param &pubElemD public element d sampled as dug
		* @param &secTA secret component of trapdoor
		* @param &dgg to generate error terms (Gaussian)
		* @param pertubationVector precomputed pertubation vector from offline sampling
		* @param *sk secret key
		*/
		void KeyGenOnline(
			const shared_ptr<typename Element::Params> elementParams,
			const usint s[],
			const Matrix<Element> &pubTA,
			const Matrix<Element> &pubElemBPos,
			const Matrix<Element> &pubElemBNeg,
			const Element &pubElemD,
			const RLWETrapdoorPair<Element> &secTA,
			typename Element::DggType &dgg,
			const shared_ptr<Matrix<Element>> perturbationVector,
			Matrix<Element> *sk
		);

		/**
		* KeyGen Function
		*
		* @param &secTA secret component of trapdoor
		* @param &dgg to generate error terms (Gaussian)
		* @return precomputed perturation vector
		*/
		shared_ptr<Matrix<Element>> KeyGenOffline(
			const RLWETrapdoorPair<Element> &secTA,
			typename Element::DggType &dgg
		);
		/**
		* Encrypt Function
		*
		* @param elementParams parameter set
		* @param &pubTA public element of trapdoor
		* @param &pubElemBPos is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to one
		* @param &pubElemBNeg is a matrix where each column corresponds to the public vector of each attribute for when the attribute is equal to zero
		* @param &pubElemD public element d sampled as dug
		* @param w[] access structure
		* @param &ptext plaintext
		* @param &dgg to generate error terms (Gaussian)
		* @param &dug select according to uniform distribution
		* @param *ctW ciphertext for attributes that are part of the attribute set w
		* @param *ctPos ciphertext based on B positive for attributes not access structure w
		* @param *ctNeg ciphertext based on B negative for attributes not access structure w
		* @param *ctC1 B^t * s + e0 part of CP-ABE algorithm for encryption/decryption
		*/
		void Encrypt(
			shared_ptr<typename Element::Params> elementParams,
			const Matrix<Element> &pubTA,
			const Matrix<Element> &pubElemBPos,
			const Matrix<Element> &pubElemBNeg,
			const Element &pubElemD,
			const int w[],
			const Element &ptext,
			typename Element::DggType &dgg,
			typename Element::DugType &dug,
			Matrix<Element> *ctW,
			Matrix<Element> *ctPos,
			Matrix<Element> *ctNeg,
			Element *ctC1
		);
		/**
		* Decrypt Function
		*
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
			const int w[],
			const usint s[],
			const Matrix<Element> &sk,
			const Matrix<Element> &ctW,
			const Matrix<Element> &ctPos,
			const Matrix<Element> &ctNeg,
			const Element &ctC1,
			Element *dtext
		);

		private:
			usint m_k; //number of bits of the modulus
			usint m_ell; //number of attributes
			usint m_N; // ring dimension
			typename Element::Integer m_q; // modulus
			usint m_m; // m = k+2
			usint m_base;
	};
}

#endif /* TRAPDOOR_LIB_CPABE_ABE_H_ */
