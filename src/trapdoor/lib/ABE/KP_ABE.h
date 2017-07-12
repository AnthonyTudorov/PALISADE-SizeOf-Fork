/*
 * Abe.h
 *
 *  Created on: Mar 23, 2017
 *      Author: savas
 */

#ifndef TRAPDOOR_LIB_ABE_ABE_H_
#define TRAPDOOR_LIB_ABE_ABE_H_

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

	/* Bit decomposition based on binary non-adjacent representation of integers
	 * Limits noise growth
	 * Temporarily here; but can be made a part of RingMat class
	 */
	int polyVec2NAFDecom (const shared_ptr<ILParams> ilParams, int k, const RingMat &B, RingMat &Psi);

	/* Digit decomposition using higher bases with balanced representation
	 * Limits noise growth
	 * Temporarily here; but can be made a part of RingMat class
	*/
	int polyVec2BalDecom (const shared_ptr<ILParams> ilParams, int32_t base, int k, const RingMat &B, RingMat &Psi);

	class KPABE{
		public:

			/**
			 * Default Constructor
			 *
			 * */
			KPABE(){}

			/**
			 * Destructor for releasing dynamic memory
			 * used for precomputed Psi
			 */
			~KPABE() { }

			/**
			 * Setup function for Private Key Generator
			 */
			void Setup(
					shared_ptr<ILParams> ilParams,
					int32_t base,
					const usint ell, // number of attributes
					DiscreteUniformGenerator &dug,  // select according to uniform distribution
					RingMat &B
			);

			/**
			 * Setup function for other users,
			*/
			void Setup(
				const shared_ptr<ILParams> ilParams,
				int32_t base,
				const usint ell
			);

			/**
			 * Evaluation function for both public keys B_i and ciphertexts C_i
			 * for the benchmark circuit
			 */
			void EvalPK(
					shared_ptr<ILParams> ilParams,
					const RingMat &B,
					RingMat *Bf
			);

			/**
			* Evaluation function for both public keys B_i and ciphertexts C_i
			* for the benchmark circuit
		    */
			void EvalCT(
			        shared_ptr<ILParams> ilParams,
					const RingMat &B,
					const usint x[],
					const RingMat &Cin,
					usint *y,
					RingMat *Cf
			);

			/**
			 * Evaluation of a single NAND gate
			 * NAND gate is universal,
			 * any Boolean function can be constructed from NAND gates
			 */
			void NANDGateEval(
				shared_ptr<ILParams> ilParams,
				const RingMat &B0,
				const RingMat &C0,
				const usint x[2],
				const RingMat &B,
				const RingMat &C,
				usint *y,
				RingMat *Bf,
				RingMat *Cf
			);
			/**
			* Evaluation of a single AND gate
			*/
			void ANDGateEval(
				shared_ptr<ILParams> ilParams,
				const usint x[2],
				const RingMat &B,
				const RingMat &C,
				usint *y,
				RingMat *Bf,
				RingMat *Cf
			);
			void NANDwNAF(
					shared_ptr<ILParams> ilParams,
					const RingMat &B0,
					const RingMat &C0,
					const usint x[],
					const RingMat &B,
					const RingMat &C,
					usint *y,
					RingMat *Bf,
					RingMat *Cf
			);

			/**
			 * Encrypt function.
			 *
			 * */
			void Encrypt(
				shared_ptr<ILParams> ilParams,
				const RingMat &A,
				const RingMat &B,
				const Poly &d,
				const usint x[],
				const Poly &pt,
				DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
				DiscreteUniformGenerator &dug,  // select according to uniform distribution
				BinaryUniformGenerator &bug,    // select according to uniform distribution binary
				RingMat &c0,
				Poly &c1
			);

			/**
			 * KeyGen
			 *
			 * */
			void KeyGen(
				const shared_ptr<ILParams> ilParams,
				const RingMat &A,                        // Public parameter $A \in R_q^{1 \times w}$
				const RingMat &Bf,                        // Public parameter $B \in R_q^{ell \times k}$
				const Poly &beta,                     // public key $d \in R_q$
				const RLWETrapdoorPair<Poly> &T_A, // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
				DiscreteGaussianGenerator &dgg,          // to generate error terms (Gaussian)
				RingMat &sKey                           // Secret key
			);

			/**
			 * Decrypt function
			 * */
			void Decrypt(
				const shared_ptr<ILParams> ilParams,
				const RingMat &sKey,
				const RingMat &CA,
				const RingMat &Cf,
				const Poly &c1,
				Poly &dtext
			);

		private:
			usint m_k; //number of bits of the modulus
			usint m_ell; //number of attributes
			usint m_N; // ring dimension
			BigInteger m_q; // modulus
			usint m_m; // m = k+2
			int32_t m_base;
	};

	const std::vector<std::vector<int>> ternaryLUT = {{1,2}, {3, 4,5}};


}

/*
 * Functions for testing
 */
int ExpErrors(int argc);
int Simulate(int argc);
int KPABE_NANDGateTest_old(usint iter);
int KPABE_NANDGateTest(usint iter, int32_t base);
int KPABE_ANDGateTest(usint iter);
int KPABE_BenchmarkCircuitTest(usint iter, int32_t base);
int KPABE_APolicyCircuitTest(int iter);
int ErrorRatesSi(int argc);
int BitSizes(int depth, usint iter);
int BitSizesBinaryDecompose(int depth, usint iter);
int BitSizeswNAFDecompose(int depth, usint iter);
int Decompose_Experiments (int base);
int Poly2NAFDecompose(usint iter);
int TestNAFDecomp (usint iter);
int TestTernaryBase_01 (int arg);
int TestBalDecomp (usint iter, int32_t base);

#endif /* TRAPDOOR_LIB_ABE_ABE_H_ */
