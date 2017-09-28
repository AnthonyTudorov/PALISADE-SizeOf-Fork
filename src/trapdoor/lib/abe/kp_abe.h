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
/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

    /**
    * Setup function for Private Key Generator (PKG)
    * Digit decomposition using higher bases with balanced representation
    * Limits noise growth
    * Temporarily here; but can be made a part of RingMat class
    *
    * @param ilParams parameter set
    * @param base is a power of two
    * @param k bit size of modulus
    * @param &matrix to be decomposed
	* @param *psi decomposed matrix
    */
	int PolyVec2BalDecom(
		const shared_ptr<ILParams> ilParams,
		int32_t base,
		int k,
		const RingMat &publElemB,
		RingMat *psi
	);

	template <class Element, class Element2>
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
			const shared_ptr<typename Element::Params> params,
			int32_t base,
			usint ell, // number of attributes
			typename Element::DugType &dug, // select according to uniform distribution
			Matrix<Element> *pubElemB
		);

		/**
		* Setup function for all parties except the Private Key Generator (PKG)
		*
		* @param ilParams parameter set
		* @param base is a power of two
		* @param ell total number of attributes
		*/
		void Setup(
			const shared_ptr<typename Element::Params> params,
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
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &pubElemB,
			Matrix<Element> *evalPubElementBf
		);

		/**
		* Evaluation function for public vectors publicElementB
		* for the benchmark circuit
		*
		* @param params parameter set
		* @param &publicElementB is a matrix where each column corresponds to the public vector of each attribute
		* @param *evalPubElement total number of attributes
		*/
		void EvalPKDCRT(
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &pubElemB,
			Matrix<Element> *evalPubElementBf,
			const shared_ptr<typename Element2::Params> ilParams
		);

		/**
		* Evaluation function for public vectors publicElementB
		* for the benchmark circuit
		*
		* @param params parameter set
		* @param &publicElementB is a matrix where each column corresponds to the public vector of each attribute
		* @param x[] array of attributes
		* @param &origCT original ciphertext
		* @param *evalAttribute evaluated value of circuit
		* @param *evalCT evaluated ciphertext value
		*/
		void EvalCTDCRT(
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &pubElemB,
			const usint x[],  //attributes
			const Matrix<Element> &origCT, // original ciphtertext
			usint *evalAttribute, // evaluated circuit
			Matrix<Element> *evalCT, //evaluated ciphertext,
			const shared_ptr<typename Element2::Params> ilParams
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
		* @param &pubElemB0
		* @param &origPubElem original matrix of public vectors for each attribute
		* @param *evalPubElem evaluated value of public element
		*/
		/*
		 * This is method for evaluating a single NAND gate
		 */
		void NANDGateEvalPK(
			const shared_ptr<ILParams> ilParams,
			const RingMat &pubElemB0,
			const RingMat &origPubElem,
			RingMat *evalPubElem
		);


		/**
		* Evaluation of a single NAND gate
		* NAND gate is universal,
		* any Boolean function can be constructed from NAND gates
		*
		* @param ilParams parameter set
		* @param &ctC0
		* @param x[] array of attributes
		* @param &origPubElem original matrix of public vectors for each attribute
		* @param &origCT original ciphertext
		* @param *evalAttribute evaluated value of circuit
		* @param *evalCT evaluated ciphertext value
		*/
		/*
		 * This is method for evaluating a single NAND gate
		 */
		void NANDGateEvalCT(
			const shared_ptr<ILParams> ilParams,
			const RingMat &ctC0,
			const usint x[],
			const RingMat &origPubElem,
			const RingMat &origCT,
			usint *evalAttribute,
			RingMat *evalCT
		);


		/**
		*Evaluation of simple AND Gate
		*
		* @param ilParams parameter set
		* @param &origPubElementB original matrix of public vectors for each attribute
		* @param *evalPubElementBf evaluated value of public element
		*/
		void ANDGateEvalPK(
			shared_ptr<ILParams> ilParams,
			const RingMat &origPubElemB,
			RingMat *evalPubElemBf
		);
		/**
		*Evaluation of simple AND Gate
		*
		* @param ilParams parameter set
		* @param x[] array of attributes
		* @param &origPubElemB original matrix of public vectors for each attribute
		* @param &origCT original ciphertext
		* @param *evalAttribute evaluated value of circuit
		* @param *evalCT evaluated ciphertext value
		*/
		void ANDGateEvalCT(
			const shared_ptr<ILParams> ilParams,
			const usint x[2], //TBA
			const RingMat &origPubElemB,
			const RingMat &origCT,
			usint *evalAttribute,
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
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &pubElemA,
			const Matrix<Element> &pubElemB,
			const Element &d, //TBA
			const usint x[],
			const Element &pt,
			typename Element::DggType &dgg,
			typename Element::DugType &dug,
			BinaryUniformGenerator &bug,
			Matrix<Element> *ctCin,
			Element *ctC1
		);

		/**
		* KeyGen Function
		*
		* @param params parameter set
		* @param &pubElementA Public parameter $A \in R_q^{1 \times w}$
		* @param &pubElementB Public parameter $B \in R_q^{ell \times k}$
		* @param &beta public key $d \in R_q$  TBA
		* @param &secElemTA Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		* @param &dgg to generate error terms (Gaussian)
		* @param *sk secret key
		*/
		void KeyGen(
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &pubElemA,
			const Matrix<Element> &pubElemB,
			const Element &beta,
			const RLWETrapdoorPair<Element> &secElemTA,
			typename Element::DggType &dgg,
			Matrix<Element> *sk
		);

		/**
		* Decrypt Function
		*
		* @param params parameter set
		* @param &sk Secret Key
		* @param &ctA ciphertext A as per paper
		* @param &evalCT evaluated ciphertext Cf pertaining to a policy
		* @param &ctC1 ciphertext C1
		* @param *dtext decrypted ciphetext
		*/
		void Decrypt(
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &sk,  //Secret key
			const Matrix<Element> &ctA, // ciphertext CA
			const Matrix<Element> &evalCT, //cipher text Cf
			const Element &ctC1,   // ciphertext C1
			Element *dtext         //decrypted plaintext
		);

		/**
		* Decode Function
		*
		* @param *dtext decoded ciphertext
		*/
		void Decode(
				Poly *dtext         //decrypted plaintext
			);


		/**
		* Evaluation of a single NAND gate
		* NAND gate is universal,
		* any Boolean function can be constructed from NAND gates
		*
		* @param params parameter set
		* @param &pubElemB0
		* @param &origPubElem original matrix of public vectors for each attribute
		* @param *evalPubElem evaluated value of public element
		* @param ilParamsConsolidated consolidated params
		*/
		/*
		 * This is method for evaluating a single NAND gate
		 */
		void NANDGateEvalPKDCRT(
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &pubElemB0,
			const Matrix<Element> &origPubElem,
			Matrix<Element> *evalPubElem,
			const shared_ptr<typename Element2::Params> ilParamsConsolidated
		);


		/**
		* Evaluation of a single NAND gate
		* NAND gate is universal,
		* any Boolean function can be constructed from NAND gates
		*
		* @param params parameter set
		* @param &ctC0
		* @param x[] array of attributes
		* @param &origPubElem original matrix of public vectors for each attribute
		* @param &origCT original ciphertext
		* @param *evalAttribute evaluated value of circuit
		* @param *evalCT evaluated ciphertext value
		* @param ilParamsConsolidated consolidated params
		*/
		/*
		 * This is method for evaluating a single NAND gate
		 */
		void NANDGateEvalCTDCRT(
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &ctC0,
			const usint x[],
			const Matrix<Element> &origPubElem,
			const Matrix<Element> &origCT,
			usint *evalAttribute,
			Matrix<Element> *evalCT,
			const shared_ptr<typename Element2::Params> ilParamsConsolidated
		);


		/**
		*Evaluation of simple Public key AND Gate DCRT
		*
		* @param params parameter set
		* @param &origPubElementB original matrix of public vectors for each attribute
		* @param *evalPubElementBf evaluated value of public element
		* @param ilParamsConsolidated consolidated params
		*/
		void ANDGateEvalPKDCRT(
			const shared_ptr<typename Element::Params> params,
			const Matrix<Element> &origPubElemB,
			Matrix<Element> *evalPubElemBf,
			const shared_ptr<typename Element2::Params> ilParamsConsolidated
		);
		/**
		*Evaluation of simple Ciphertext AND Gate
		*
		* @param params parameter set
		* @param x[] array of attributes
		* @param &origPubElemB original matrix of public vectors for each attribute
		* @param &origCT original ciphertext
		* @param *evalAttribute evaluated value of circuit
		* @param *evalCT evaluated ciphertext value
		* @param ilParamsConsolidated consolidated params
		*/
		void ANDGateEvalCTDCRT(
			const shared_ptr<typename Element::Params> params,
			const usint x[2], //TBA
			const Matrix<Element> &origPubElemB,
			const Matrix<Element> &origCT,
			usint *evalAttribute,
			Matrix<Element> *evalCT,
			const shared_ptr<typename Element2::Params> ilParamsConsolidated
	);


	private:
		usint m_k; //number of bits of the modulus
		usint m_ell; //number of attributes
		usint m_N; // ring dimension
		BigInteger m_q; // modulus
		usint m_m; // m = k+2
		int32_t m_base; //base, a power of two
	};

}

#endif /* TRAPDOOR_LIB_ABE_ABE_H_ */
