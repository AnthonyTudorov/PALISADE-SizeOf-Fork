/**
 * @file lwetbolinearsecret.h Implementation of token-based obfuscation of linear functions (secret-key version)
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

#ifndef LBCRYPTO_OBFUSCATE_LWETBOLINEARSECRET_H
#define LBCRYPTO_OBFUSCATE_LWETBOLINEARSECRET_H

#include <cmath>
#include <vector>
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "math/backend.h"
#include "math/matrix.cpp"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	struct LWETBOKeys{
		shared_ptr<Matrix<NativeInteger>> m_secretKey;
		shared_ptr<Matrix<NativeInteger>> m_publicRandomVector;
	};

	/**
	 * @brief LWE-based token-based obfuscation of linear functions
	 */
	class LWETBOLinearSecret {
	public:

		typedef shared_ptr<Matrix<NativeInteger>> NativeMatrixPtr;
		typedef Matrix<NativeInteger> NativeMatrix;

		/**
		 * Constructor
		 *
		 * @param N the dimension
		 * @param n LWE security parameter
		 * @param wmax infinity norm of the weights vector
		 * @param pmax infinity norm of input data vector
		 */
		explicit LWETBOLinearSecret(usint N, usint n, usint wmax, usint pmax);

		/**
		 * Gets the LWE security parameter
		 * @return the LWE security parameter
		 */
		usint GetSecurityParameter() const {return m_n;}

		/**
		 * Gets the log of the modulus
		 * @return the log of the modulus
		 */
		usint GetLogModulus() const;

		/**
		 * Gets the weight infinity norm
		 * @return the weight norm
		 */
		usint GetWeightNorm() const {return m_wmax;}

		/**
		 * Gets the "plaintext" modulus p used by the LWE scheme
		 * @return p
		 */
		uint64_t GetPlaintextModulus() const {return m_p;}

		/**
		 * Gets "ciphertext" modulus for the LWE problem
		 * @return the ciphertext modulus q
		 */
		NativeInteger GetModulus() const {return m_modulus;}

		/**
		 * Gets the dimension N
		 * @return the dimension N
		 */
		usint GetDimension() const {return m_N;}

		/**
		 * Generate N random secret vectors Z_q^n and public random vector a
		 * @return the secret keys and public random vector
		 */
		LWETBOKeys KeyGen() const;

		/**
		 * Generate token t = \Sum{w_i s_i} \in Z_q^n
		 *
		 * @param keys secret keys
		 * @param input input data vector
		 * @return the token
		 */
		NativeMatrixPtr TokenGen(const NativeMatrixPtr keys, const NativeMatrixPtr input) const;

		/**
		 * Generates an encryption of weights (obfuscated program)
		 *
		 * @param keyPair secret keys + public random vector
		 * @param weigts the weights vector
		 * @return the obfuscated program
		 */
		NativeMatrixPtr Obfuscate(const LWETBOKeys &keyPair, const NativeMatrixPtr weights) const;

		/**
		 * Evaluates \Sum{w_i x_i} using obfuscated program
		 *
		 * @param input input data vector
		 * @param ciphertext obfuscated program
		 * @param publicRandomVector public random vector
		 * @param token the token for the input data vector
		 * @return the result of the summation
		 */
		NativeInteger Evaluate(const NativeMatrixPtr input, const NativeMatrixPtr ciphertext,
				const NativeMatrixPtr publicRandomVector, const NativeMatrixPtr token) const;

		/**
		 * Evaluates \Sum{w_i x_i} using cleartext program
		 *
		 * @param input input data vector
		 * @param weigts the weights vector
		 * @return the result of the summation
		 */
		NativeInteger EvaluateClear(const NativeMatrixPtr input, const NativeMatrixPtr weights) const;

	private:

		// Dimension - size of weight/data vectors
		usint m_N;

		// LWE security parameter
		usint m_n;

		// Infinity norm for the weight vector
		usint m_wmax;

		// Plaintext modulus p
		uint64_t m_p;

		// Infinity norm for the input data vector
		usint m_pmax;

		// LWE "ciphertext" modulus q
		NativeInteger m_modulus;

		// Discrete Gaussian distribution for generating the noise in the LWE encryption
		DiscreteGaussianGeneratorImpl<NativeInteger,NativeVector> m_dgg;

		/**
		 * Method to estimate the modulus
		 * Used as a subroutine by constructor
		 *
		 * @return estimated value q of modulus
		 */
		double EstimateModulus();

	};

} // namespace lbcrypto ends

#endif
