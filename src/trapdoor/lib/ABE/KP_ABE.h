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
 * This code provides functionality for Key-policy attribute-based encryption
 * (KP-ABE). The algorithms and naming conventions can be found from
 * this paper: https://eprint.iacr.org/2017/601.pdf
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

	/**
 	* Bit decomposition based on binary non-adjacent representation of integers
	* Limits noise growth
	* Temporarily here; but can be made a part of RingMat class
	*
	* @param ilParams parameter set
	* @param k bit size of modulus
	* @param *publicElementB is a matrix where each column corresponds to the public vector of each attribute
	* @param *psi bit decomposition of publicElementB
	*/
	int polyVec2NAFDecom(
			const shared_ptr<ILParams> ilParams,
			int k,
			const RingMat &pubElemB,
			RingMat *psi
		);

    /**
    * Setup function for Private Key Generator (PKG)
    * Digit decomposition using higher bases with balanced representation
    * Limits noise growth
    * Temporarily here; but can be made a part of RingMat class
    *
    * @param ilParams parameter set
    * @param base is a power of two
    * @param k bit size of modulus
    * @param *publicElementB is a matrix where each column corresponds to the public vector of each attribute
	* @param *psi bit decomposition of publicElementB
    */
	int polyVec2BalDecom(
			const shared_ptr<ILParams> ilParams,
			int32_t base,
			int k,
			const RingMat &publElemB,
			RingMat *psi
		);

class KPABE {
public:

	/**
	 * Default Constructor
	 *
	 */
	KPABE() {
	}

	/**
	 * Destructor for releasing dynamic memory
	 * used for precomputed psi
	 *
	 */
	~KPABE() {
	}

	/**
	* Setup function for Private Key Generator (PKG)
	*
	* @param ilParams parameter set
	* @param base is a power of two
	* @param ell total number of attributes
	* @param &dug
	* @param *publicElementB is a matrix where each column corresponds to the public vector of each attribute
	*/
	void Setup(
			const shared_ptr<ILParams> ilParams,
			int32_t base,
			usint ell, // number of attributes
			const DiscreteUniformGenerator &dug, // select according to uniform distribution
			RingMat *pubElemB
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
	* Evaluation function for public vectors publicElementB
	* for the benchmark circuit
	*
	* @param ilParams parameter set
	* @param &publicElementB is a matrix where each column corresponds to the public vector of each attribute
	* @param *evalPubElement total number of attributes
	*/
	void EvalPK(
			const shared_ptr<ILParams> ilParams,
			const RingMat &pubElemB,
			RingMat *evalPubElementBf
		);

	/**
	* Evaluation function for public vectors publicElementB
	* for the benchmark circuit
	*
	* @param ilParams parameter set
	* @param &publicElementB is a matrix where each column corresponds to the public vector of each attribute
	* @param x[] array of attributes
	* @param &origCT original ciphertext
	* @param *evalAttribute evaluated value of circuit
	* @param *evalCT evaluated ciphertext value
	*/
	void EvalCT(
			const shared_ptr<ILParams> ilParams,
			const RingMat &pubElemB,
			const usint x[],  //attributes
			const RingMat &origCT, // original ciphtertext
			usint *evalAttribute, // evaluated circuit
			RingMat *evalCT //evaluated ciphertext
		);

	/**
	* Evaluation of a single NAND gate
	* NAND gate is universal,
	* any Boolean function can be constructed from NAND gates
	*
	* @param ilParams parameter set
	* @param &B0
	* @param &C0
	* @param x[] array of attributes
	* @param &origPubElementB original matrix of public vectors for each attribute
	* @param &origCT original ciphertext
	* @param *evalAttribute evaluated value of circuit
	* @param *evalPubElementBf evaluated value of public element
	* @param *evalCT evaluated ciphertext value
	*/
	void NANDGateEval(
			const shared_ptr<ILParams> ilParams,
			const RingMat &B0, //TBA
			const RingMat &C0, //TBA
			const usint x[2],
			const RingMat &origPubElemB,
			const RingMat &origCT,
			usint *evalAttribute, //attribute results
			RingMat *evalPubElemBf,
			RingMat *evalCT
		);

	/**
	*Evaluation of simple AND Gate
	*
	* @param ilParams parameter set
	* @param &B0
	* @param &C0
	* @param x[] array of attributes
	* @param &origPubElementB original matrix of public vectors for each attribute
	* @param &origCT original ciphertext
	* @param *evalAttribute evaluated value of circuit
	* @param *evalPubElementBf evaluated value of public element
	* @param *evalCT evaluated ciphertext value
	*/
	void ANDGateEval(
			const shared_ptr<ILParams> ilParams,
			const usint x[2], //TBA
			const RingMat &origPubElemB,
			const RingMat &origCT,
			usint *evalAttribute,
			RingMat *evalPubElem,
			RingMat *evalCT
		);

	/**
	* Evaluation of a single NAND gate NAF
	* NAND with NAF gate is universal,
	* any Boolean function can be constructed from NAND gates
	* TO BE IMPLEMENTED
	*
	* @param ilParams parameter set
	* @param &B0
	* @param &C0
	* @param x[] array of attributes
	* @param &origPubElementB original matrix of public vectors for each attribute
	* @param &origCT original ciphertext
	* @param *evalAttribute evaluated value of circuit
	* @param *evalPubElementBf evaluated value of public element
	* @param *evalCT evaluated ciphertext value
	*/
	void NANDwNAF(
			const shared_ptr<ILParams> ilParams,
			const RingMat &B0, //TBA
			const RingMat &C0, //TBA
			const usint x[],
			const RingMat &origPubElemB,
			const RingMat &origCT,
			usint *evalAttribute,
			RingMat *evalPubElemBf,
			RingMat *evalCT
		);

	/**
	* Encrypt Function
	*
	* @param ilParams parameter set
	* @param &pubElementA
	* @param &pubElementB
	* @param &d
	* @param x[] array of attributes
	* @param &pt
	* @param &dgg to generate error terms (Gaussian)
	* @param &dug select according to uniform distribution
	* @param &bug select according to uniform distribution binary
	* @param *ctCin resulting ciphertext Cin as per algorithm
	* @param *ctC1 c1, a separate part of the cipertext as per the algorithm
	*/
	void Encrypt(
			shared_ptr<ILParams> ilParams,
			const RingMat &pubElemA,
			const RingMat &pubElemB,
			const Poly &d, //TBA
			const usint x[],
			const Poly &pt,
			DiscreteGaussianGenerator &dgg,
			DiscreteUniformGenerator &dug,
			BinaryUniformGenerator &bug,
			RingMat *ctCin,
			Poly *ctC1
		);

	/**
	* Encrypt Function
	*
	* @param ilParams parameter set
	* @param &pubElementA Public parameter $A \in R_q^{1 \times w}$
	* @param &pubElementB Public parameter $B \in R_q^{ell \times k}$
	* @param &beta public key $d \in R_q$  TBA
	* @param &secElemTA Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
	* @param &dgg to generate error terms (Gaussian)
	* @param *sk secret key
	*/
	void KeyGen(
			const shared_ptr<ILParams> ilParams,
			const RingMat &pubElemA,
			const RingMat &pubElemB,
			const Poly &beta,
			const RLWETrapdoorPair<Poly> &secElemTA,
		    DiscreteGaussianGenerator &dgg,
			RingMat *sk
		);

	/**
	* Encrypt Function
	*
	* @param ilParams parameter set
	* @param &sk Secret Key
	* @param &ctA ciphertext A as per paper
	* @param &evalCT evaluated ciphertext Cf pertaining to a policy
	* @param &ctC1 ciphertext C1
	* @param *dtext decrypted ciphetext
	*/
	void Decrypt(
		    const shared_ptr<ILParams> ilParams,
		    const RingMat &sk,  //Secret key
		    const RingMat &ctA, // ciphertext CA
		    const RingMat &evalCT, //cipher text Cf
		    const Poly &ctC1,   // ciphertext C1
		    Poly *dtext         //decrypted plaintext
		);

private:
	usint m_k; //number of bits of the modulus
	usint m_ell; //number of attributes
	usint m_N; // ring dimension
	BigInteger m_q; // modulus
	usint m_m; // m = k+2
	int32_t m_base; //base, a power of two
};

const std::vector<std::vector<int>> ternaryLUT = { { 1, 2 }, { 3, 4, 5 } };

}

/*
 * Functions for testing
 */
int KPABE_NANDGateTest(usint iter, int32_t base);
int KPABE_ANDGateTest(usint iter);
int KPABE_BenchmarkCircuitTest(usint iter, int32_t base);
int KPABE_APolicyCircuitTest(int iter);

#endif /* TRAPDOOR_LIB_ABE_ABE_H_ */
