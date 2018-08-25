/**
 * @file gsw.cpp Provides implementation of the GSW variant described in
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

#ifndef _LBCRYPTO_SUBGAUSSIAN_GSW_CPP
#define _LBCRYPTO_SUBGAUSSIAN_GSW_CPP

#include "gsw.h"
#include "math/matrix-impl.cpp"

namespace lbcrypto {

	template class Matrix<NativeInteger>;

	template <class Integer,class Vector>
	shared_ptr<GSWSecretKey<Integer>> GSWScheme<Integer,Vector>::SecretKeyGen() const
	{
		shared_ptr<GSWSecretKey<Integer>> sk(new GSWSecretKey<Integer>([&]()
				{return m_cryptoParams.GetDgg().GenerateInteger(m_cryptoParams.GetModulus());}, m_cryptoParams.Getn()-1, 1));
		return sk;
	}

	template <class Integer,class Vector>
	shared_ptr<GSWCiphertext<Integer>> GSWScheme<Integer,Vector>::Encrypt(const GSWPlaintext<Integer> &plaintext,
			const shared_ptr<GSWSecretKey<Integer>> sk) const
	{
		const Integer &modulus = m_cryptoParams.GetModulus();
		Matrix<Integer> cbar([&](){return m_cryptoParams.GetDug().GenerateInteger();}, m_cryptoParams.Getn()-1, m_cryptoParams.Getm());
		Matrix<Integer> et([&](){return m_cryptoParams.GetDgg().GenerateInteger(modulus);}, 1,m_cryptoParams.Getm());
		//Matrix<Integer> et([&](){return Integer(0);}, 1,m_cryptoParams.Getm());
		Matrix<Integer> skt = sk->Transpose();
		Matrix<Integer> bt = et.ModSubEq((skt.Mult(cbar)).ModEq(modulus),modulus);
		Matrix<Integer> cStack = cbar.VStack(bt);
		Matrix<Integer> g([&](){return Integer(0);}, m_cryptoParams.Getn(),m_cryptoParams.Getm());
		g = g.GadgetVector(m_cryptoParams.GetBase());
		//std::cout << g << std::endl;
		shared_ptr<Matrix<Integer>> c(new Matrix<Integer>((cStack + (g.ScalarMult(plaintext)).ModEq(modulus)).ModEq(modulus)));
		return c;
	}

	template <class Integer,class Vector>
	GSWPlaintext<Integer> GSWScheme<Integer,Vector>::Decrypt(const shared_ptr<GSWCiphertext<Integer>> ciphertext,
			const shared_ptr<GSWSecretKey<Integer>> sk) const
	{
		const Integer &modulus = m_cryptoParams.GetModulus();
		GSWPlaintext<Integer> mu = Integer(0);
		for (size_t i = 0; i <  m_cryptoParams.Getn()-1; i++)
		{
			mu += ((*sk)(i,0)*(*ciphertext)(i,m_cryptoParams.Getm()-2)).ModEq(modulus);
		}
		mu += ((*ciphertext)(m_cryptoParams.Getn()-1,m_cryptoParams.Getm()-2));

		mu.ModEq(modulus);

		std::cout << mu << std::endl;

		Integer half = modulus >> 1;
		if (mu > half)
			mu = modulus - mu;

		return mu.MultiplyAndRound(m_cryptoParams.GetBase(),m_cryptoParams.GetModulus());

		//return mu;
	}

}

#endif
