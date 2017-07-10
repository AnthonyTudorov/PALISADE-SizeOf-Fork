/*
 * CPABE.h
 *
 *  Created on: Mar 23, 2017
 *      Author: savas
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
			 * */
			IBE(){}

			/**
			 * Destructor for releasing dynamic memory
			 * used for precomputed Psi
			 */
			~IBE() { }

			/**
			 * Setup function for Private Key Generator
			 */
			std::pair<RingMat, RLWETrapdoorPair<Poly>> Setup(
				shared_ptr<ILParams> ilParams,
				int32_t base,
				DiscreteUniformGenerator &dug  // select according to uniform distribution
			);

			/**
			 * Setup function for other users,
			*/
			void Setup(
				const shared_ptr<ILParams> ilParams,
				int32_t base
			);

			/**
			 * KeyGen
			 * */
			void KeyGen(
				const shared_ptr<ILParams> ilParams,
				const RingMat &A,                         // Public parameter $B \in R_q^{ell \times k}$
				const Poly &u,                  	  // public key of the user $u \in R_q$
				const RLWETrapdoorPair<Poly> &T_A,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
				DiscreteGaussianGenerator &dgg,           // to generate error terms (Gaussian)
				RingMat &sKey                             // Secret key
			);

			/**
			 * Encrypt function.
			 * */
			void Encrypt(
				shared_ptr<ILParams> ilParams,
				const RingMat &A,
				const Poly &u,
				const Poly &pt,
				DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
				DiscreteUniformGenerator &dug,  // select according to uniform distribution
				BinaryUniformGenerator &bug,    // select according to uniform distribution binary
				RingMat &C0,
				Poly &c1
			);

			/**
			 * Decrypt function
			 * */
			void Decrypt(
				const shared_ptr<ILParams> ilParams,
				const RingMat &sKey,
				const RingMat &C0,
				const Poly &c1,
				Poly &dtext
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
