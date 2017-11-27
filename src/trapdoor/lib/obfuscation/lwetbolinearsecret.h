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

	struct LWETBOKeyPair{
		shared_ptr<Matrix<native_int::BigInteger>> m_secretKey;
		shared_ptr<Matrix<native_int::BigInteger>> m_publicKey;
	};

	/**
	 * @brief LWE-based token-based obfuscation of linear functions
	 */
	class LWETBOLinearSecret {
	public:

		typedef native_int::BigInteger NativeInteger;
		typedef shared_ptr<Matrix<NativeInteger>> NativeMatrixPtr;
		typedef Matrix<NativeInteger> NativeMatrix;

		//typedef shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> KeyType;

		/**
		 * Constructor
		 *
		 * @param N the dimension of linear system
		 * @param n LWE security parameter
		 * @param wmax weight modulus
		 * @param p infinity norm of input data
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

		usint GetWeightNorm() const {return m_wmax;}

		usint GetPlaintextModulus() const {return m_p;}

		NativeInteger GetModulus() const {return m_modulus;}

		usint GetDimension() const {return m_N;}

		LWETBOKeyPair KeyGen() const;

		NativeMatrixPtr TokenGen(const NativeMatrixPtr keys, const NativeMatrixPtr input) const;

		NativeMatrixPtr Encrypt(const LWETBOKeyPair &keyPair, const NativeMatrixPtr weights) const;

		NativeInteger Evaluate(const NativeMatrixPtr input, const NativeMatrixPtr ciphertext,
				const NativeMatrixPtr publicKey, const NativeMatrixPtr token) const;

		NativeInteger EvaluateClear(const NativeMatrixPtr input, const NativeMatrixPtr weights) const;

	private:

		usint m_N;
		usint m_n;
		usint m_wmax;
		usint m_p;
		usint m_pmax;

		NativeInteger m_modulus;

		DiscreteGaussianGeneratorImpl<NativeInteger,native_int::BigVector> m_dgg;

		/**
		 * Method to estimed the modulus
		 * Used as a subroutine by constructor
		 *
		 * @return estimated value q of modulus
		 */
		double EstimateModulus();

	};

} // namespace lbcrypto ends

#endif
