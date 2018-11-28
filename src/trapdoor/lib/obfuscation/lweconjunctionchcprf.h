/**
 * @file lweconjunctionchcprf.h Implementation of conjunction constraint-hiding constrained PRFs as described in https://eprint.iacr.org/2017/143.pdf
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

#ifndef LBCRYPTO_OBFUSCATE_LWECONJUNCTIONCHCPRF_H
#define LBCRYPTO_OBFUSCATE_LWECONJUNCTIONCHCPRF_H

#include <cmath>
#include <vector>
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
	 * @brief LWE conjunction CHCPRF scheme as described in https://eprint.iacr.org/2017/143.pdf
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LWEConjunctionCHCPRFAlgorithm {
	public:

		/**
		 * Constructor
		 *
		 * @param base base for G-sampling
		 * @param chunkSize number of bits encoded by one encoding matrix
		 * @param length the input length
		 * @param n ring dimension
		 */
		explicit LWEConjunctionCHCPRFAlgorithm(usint base, usint chunkSize, usint length, usint n);

		/**
		 * Gets the ring dimension
		 * @return the ring dimension
		 */
		usint GetRingDimension() const;

		/**
		 * Gets the log of the modulus
		 * @return the log of the modulus
		 */
		usint GetLogModulus() const;

		/**
		 * Method to generate unconstrained PRF key
		 *
		 * @return unconstrained PRF key
		 */
		shared_ptr<vector<vector<Element>>> KeyGen();

		/**
		 * Method to constrain key by conjunction pattern
		 *
		 * @param s unconstrained PRF key
		 * @param pattern conjunction pattern
		 * @return constrained key
		 */
		shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> Constrain(const shared_ptr<vector<vector<Element>>> s, const std::string &pattern);

		/**
		 * Method to evaluate PRF using unconstrained PRF key and input
		 *
		 * @param s unconstrained PRF key
		 * @param input PRF input
		 * @return PRF output
		 */
		shared_ptr<vector<NativePoly>> Evaluate(const shared_ptr<vector<vector<Element>>> s, const std::string &input) const;

		/**
		 * Method to evaluate PRF using constrained PRF key and input
		 *
		 * @param D constrained PRF key
		 * @param input PRF input
		 * @return PRF output
		 */
		shared_ptr<vector<NativePoly>> Evaluate(const shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> D, const std::string &input) const;

		/**
		 * Compares the evaluation results using constrained and unconstrained keys
		 *
		 * @param y evaluation result using the constrained key
		 * @param yPrime evaluation result using the unconstrained key
		 * @return true if the inputs match
		 */
		bool EqualTest(shared_ptr<vector<NativePoly>> y, shared_ptr<vector<NativePoly>> yPrime) const{
			return (*y == *yPrime);
		}

	private:
		/**
		 * Method to find modulus estimate given ring dimension n
		 * Used as a subroutine by constructor
		 *
		 * @param n ring dimension
		 * @return estimated value q of modulus
		 */
		double EstimateRingModulus(usint n);

		/**
		 * Method to create element parameters for given q and n
		 * Used as a subroutine by constructor
		 *
		 * @param q estimated value of modulus
		 * @param n ring dimension
		 * @return element parameters
		 */
		shared_ptr<typename Element::Params> GenerateElemParams(double q, usint n) const;

		/**
		 * Method to generate A's and T's for GGH15 multi-linear map encoding
		 * Used as a subroutine by constructor
		 */
		void EncodingParamsGen();

		/**
		 * Method to encode elem by path Ai -> Aj
		 * Used as a subroutine by Constrain
		 *
		 * @param i path start node
		 * @param j path end node
		 * @param elem element to encode
		 * @return encoding of elem
		 */
		shared_ptr<Matrix<Element>> Encode(usint i, usint j, const Element &elem);

		shared_ptr<vector<NativePoly>> TransformMatrixToPRFOutput(const Matrix<Element> &matrix) const;

		usint m_base;
		usint m_chunkSize;
		usint m_length;
		usint m_adjustedLength;
		usint m_chunkExponent;

		shared_ptr<typename Element::Params> m_elemParams;

		DCRTPoly::DggType m_dgg;
		DCRTPoly::DggType m_dggLargeSigma;
		//DCRTPoly::TugType m_tug;

		shared_ptr<vector<Matrix<Element>>> m_A;
		shared_ptr<vector<RLWETrapdoorPair<Element>>> m_T;

		// used during encryption
		vector<NativeInteger> m_CRTDeltaTable;

		// when log2 qi <= 44 bits
		// Stores a precomputed table of ((p*[(Q/qi)^{-1}]_qi)%qi)/qi
		std::vector<double> m_CRTDecryptionFloatTable;

		// when 44 < log2 qi <= 57  bits
		// Stores a precomputed table of ((p*[(Q/qi)^{-1}]_qi)%qi)/qi
		std::vector<long double> m_CRTDecryptionExtFloatTable;

		// when log2 qi = 58..60 bits
		// Stores a precomputed table of ((p*[(Q/qi)^{-1}]_qi)%qi)/qi
		std::vector<QuadFloat> m_CRTDecryptionQuadFloatTable;

		// Stores a precomputed table of floor[(p*[(Q/qi)^{-1}]_qi)/qi]_p
		std::vector<NativeInteger> m_CRTDecryptionIntTable;

		// Stores an NTL precomputation for the precomputed table of floor[(p*[(Q/qi)^{-1}]_qi)/qi]_p
		std::vector<NativeInteger> m_CRTDecryptionIntPreconTable;

	};

	#if 0
	template <>
	shared_ptr<typename DCRTPoly::Params> LWEConjunctionCHCPRFAlgorithm<DCRTPoly>::GenerateElemParams(double q, usint n) const;
        #endif
} // namespace lbcrypto ends

#endif
