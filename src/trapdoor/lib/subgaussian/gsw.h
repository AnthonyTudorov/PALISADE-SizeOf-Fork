/**
 * @file gsw.h Provides implementation of the GSW variant described in
 * https://eprint.iacr.org/2014/094
 *
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2018, New Jersey Institute of Technology (NJIT)
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

#include "math/matrix.h"

#ifndef LBCRYPTO_SUBGAUSSIAN_GSW_H
#define LBCRYPTO_SUBGAUSSIAN_GSW_H

namespace lbcrypto {

// dimension Z_q^n
template <class Integer>
using GSWSecretKey = Matrix<Integer>;

// dimension Z_q^m \times n
template <class Integer>
using GSWPublicKey = Matrix<Integer> ;

// dimension Z_q^n \times n l
template <class Integer>
using GSWCiphertext = Matrix<Integer>;

// dimension Z_q
template <class Integer>
using GSWPlaintext = Integer;

template <class Integer>
class GSWCryptoParameters
{
public:
	GSWCryptoParameters() : m_n(0), m_l(0), m_m(0), m_q(Integer(0)) {;}
	GSWCryptoParameters(uint32_t n, uint32_t l, uint32_t m, const Integer &q) : m_n(n), m_l(l), m_m(m), m_q(q) {;}
private:
	uint32_t m_n;
	uint32_t m_l;
	uint32_t m_m;
	Integer m_q;
};

template <class Integer>
class GSWScheme
{
public:
	void Setup(uint32_t n, uint32_t l, uint32_t m, const Integer &q) {
		m_cryptoParams = GSWCryptoParameters<Integer>(n,l,m,q);
	}

	shared_ptr<GSWSecretKey<Integer>> SecretKeyGen() const;
	shared_ptr<GSWPublicKey<Integer>> PublicKeyGen(const shared_ptr<GSWSecretKey<Integer>>) const;
	shared_ptr<GSWCiphertext<Integer>> Encrypt(const GSWPlaintext<Integer> &plaintext, const shared_ptr<GSWSecretKey<Integer>>) const;
	GSWPlaintext<Integer> Decrypt(const GSWCiphertext<Integer> &ciphertext, const shared_ptr<GSWSecretKey<Integer>>) const;

	shared_ptr<GSWCiphertext<Integer>> EvalAdd(const shared_ptr<GSWCiphertext<Integer>>, const shared_ptr<GSWCiphertext<Integer>>);
	shared_ptr<GSWCiphertext<Integer>> EvalMult(const shared_ptr<GSWCiphertext<Integer>>, const shared_ptr<GSWCiphertext<Integer>>);

private:
	GSWCryptoParameters<Integer> m_cryptoParams;

};


}

#endif
